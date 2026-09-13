from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ParameterType(str, Enum):
    INTEGER = "Integer"
    UUID_GUID = "UUID/GUID"
    JSON_OBJECT = "JSON Object"
    COMPLEX = "Complex"
    ARRAY = "Array"
    PERSONAL_INFORMATION = "Personal Information"
    STRING = "String"
    OTHER = "Other"


@dataclass
class ParameterInfo:
    name: str
    location: str
    required: bool
    schema: Dict[str, Any]
    description: str = ""
    tags: List[str] = field(default_factory=list)

    is_resource_identifier: bool = False
    resource_id_reasons: List[str] = field(default_factory=list)
    classified_type: ParameterType = ParameterType.OTHER

    @property
    def normalized_name(self) -> str:
        return re.sub(r"[^a-zA-Z0-9]", "", self.name).lower()


@dataclass
class EndpointInfo:
    path: str
    method: str
    operation: Dict[str, Any]
    parameters: List[ParameterInfo]

    requires_authentication: bool = False
    supported_methods: Set[str] = field(default_factory=set)


@dataclass
class Finding:
    path: str
    method: str
    technique: str
    matched: bool
    reason: str
    parameters: List[str] = field(default_factory=list)
    severity: str = "Medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "technique": self.technique,
            "matched": self.matched,
            "reason": self.reason,
            "parameters": self.parameters,
            "severity": self.severity,
        }


class OpenAPIResourceIDDetector:
    HTTP_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    }

    # 사전 정의된 Resource ID 후보 이름
    RESOURCE_ID_WORDS = {
        "name",
        "filename",
        "file",
        "group",
        "key",
        "phone",
        "email",
        "account",
        "user",
        "username",
        "profile",
        "bucket",
        "folder",
        "project",
        "tenant",
        "organization",
        "org",
        "resource",
        "object",
        "item",
    }

    # ID suffix / exact match 규칙
    ID_NAME_PATTERNS = [
        re.compile(r"^(id|_id)$", re.IGNORECASE),
        re.compile(r".*[_-]?id$", re.IGNORECASE),
        re.compile(r".*[_-]?uuid$", re.IGNORECASE),
        re.compile(r".*[_-]?guid$", re.IGNORECASE),
    ]

    IDENTIFIER_DESCRIPTION_PATTERN = re.compile(
        r"\b(id|uuid|guid|identifier)\b",
        re.IGNORECASE,
    )

    ACTION_VERBS = {
        "add",
        "create",
        "edit",
        "update",
        "delete",
        "remove",
        "modify",
        "change",
        "reset",
        "enable",
        "disable",
        "activate",
        "deactivate",
        "verify",
        "validate",
        "approve",
        "reject",
        "share",
        "move",
        "copy",
        "restore",
    }

    def __init__(self, openapi_document: Dict[str, Any]):
        self.document = openapi_document
        self.paths = openapi_document.get("paths", {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        endpoints = self.extract_endpoints()
        findings: List[Finding] = []

        for endpoint in endpoints:
            findings.extend(self.match_attack_vectors(endpoint, endpoints))

        return {
            "openapi_version": self.document.get("openapi"),
            "endpoints": [
                {
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "requires_authentication": endpoint.requires_authentication,
                    "parameters": [
                        {
                            "name": parameter.name,
                            "location": parameter.location,
                            "required": parameter.required,
                            "is_resource_identifier": (
                                parameter.is_resource_identifier
                            ),
                            "resource_id_reasons": (
                                parameter.resource_id_reasons
                            ),
                            "classified_type": (
                                parameter.classified_type.value
                            ),
                        }
                        for parameter in endpoint.parameters
                    ],
                }
                for endpoint in endpoints
            ],
            "findings": [finding.to_dict() for finding in findings],
        }

    def extract_endpoints(self) -> List[EndpointInfo]:
        endpoints: List[EndpointInfo] = []

        for path, path_item in self.paths.items():
            if not isinstance(path_item, dict):
                continue

            path_level_parameters = path_item.get("parameters", [])

            for method, operation in path_item.items():
                method_lower = method.lower()

                if method_lower not in self.HTTP_METHODS:
                    continue

                if not isinstance(operation, dict):
                    continue

                operation_parameters = operation.get("parameters", [])
                raw_parameters = (
                    path_level_parameters + operation_parameters
                )

                parameters = [
                    self.build_parameter_info(
                        parameter=parameter,
                        path=path,
                        operation=operation,
                    )
                    for parameter in raw_parameters
                    if self.is_valid_parameter(parameter)
                ]

                endpoints.append(
                    EndpointInfo(
                        path=path,
                        method=method_lower.upper(),
                        operation=operation,
                        parameters=parameters,
                        requires_authentication=(
                            self.has_security_requirement(operation)
                        ),
                        supported_methods=self.get_supported_methods(path_item),
                    )
                )

        return endpoints

    def match_attack_vectors(
        self,
        endpoint: EndpointInfo,
        all_endpoints: List[EndpointInfo],
    ) -> List[Finding]:
        findings = [
            self.match_dumb_enumeration(endpoint),
            self.match_a_priori_enumeration(endpoint),
            self.match_list_appending(endpoint),
            self.match_token_manipulation(endpoint),
            self.match_parameter_pollution(endpoint),
            self.match_verb_tampering(endpoint, all_endpoints),
        ]

        return findings

    # ------------------------------------------------------------------
    # Step 1, 2: Resource ID extraction and type classification
    # ------------------------------------------------------------------

    def build_parameter_info(
        self,
        parameter: Dict[str, Any],
        path: str,
        operation: Dict[str, Any],
    ) -> ParameterInfo:
        name = str(parameter.get("name", ""))
        location = str(parameter.get("in", "")).lower()
        schema = parameter.get("schema", {})

        if not isinstance(schema, dict):
            schema = {}

        description = str(
            parameter.get("description")
            or schema.get("description")
            or ""
        )

        tags = self.extract_tags(parameter, operation)

        is_resource_id, reasons = self.is_resource_identifier(
            name=name,
            location=location,
            path=path,
            description=description,
            tags=tags,
            schema=schema,
        )

        classified_type = self.classify_parameter_type(
            name=name,
            schema=schema,
            is_resource_identifier=is_resource_id,
        )

        return ParameterInfo(
            name=name,
            location=location,
            required=bool(parameter.get("required", False)),
            schema=schema,
            description=description,
            tags=tags,
            is_resource_identifier=is_resource_id,
            resource_id_reasons=reasons,
            classified_type=classified_type,
        )

    def is_resource_identifier(
        self,
        name: str,
        location: str,
        path: str,
        description: str,
        tags: List[str],
        schema: Dict[str, Any],
    ) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        normalized_name = self.normalize_name(name)

        # 이름 기준
        if any(
            pattern.match(name)
            for pattern in self.ID_NAME_PATTERNS
        ):
            reasons.append("parameter name matches ID/UUID/GUID rule")

        if normalized_name in {
            self.normalize_name(word)
            for word in self.RESOURCE_ID_WORDS
        }:
            reasons.append("parameter name matches predefined identifier word")

        # 경로와 파라미터 이름 유사성
        path_variables = self.extract_path_variables(path)

        for path_variable in path_variables:
            if self.names_are_similar(name, path_variable):
                reasons.append(
                    "parameter name is similar to path variable"
                )

        # 액션 동사가 포함된 경로
        path_tokens = self.tokenize(path)

        if self.ACTION_VERBS.intersection(path_tokens):
            if name in path_variables or self.names_are_similar(
                name,
                self.closest_path_variable(name, path_variables),
            ):
                reasons.append(
                    "action verb exists in path and parameter references path resource"
                )

        # Description 및 tag
        metadata_text = " ".join(
            [description] + tags + [str(schema.get("description", ""))]
        )

        if self.IDENTIFIER_DESCRIPTION_PATTERN.search(metadata_text):
            reasons.append(
                "description or tag contains ID/UUID/GUID/identifier"
            )

        # 명세서의 vendor extension을 통한 직접 표시도 허용
        if (
            parameter.get("x-resource-id") is True
            or schema.get("x-resource-id") is True
        ):
            reasons.append("explicit x-resource-id marker")

        return bool(reasons), reasons

    def classify_parameter_type(
        self,
        name: str,
        schema: Dict[str, Any],
        is_resource_identifier: bool,
    ) -> ParameterType:
        schema_type = schema.get("type")
        normalized_name = self.normalize_name(name)

        # JSON Object
        if schema_type == "object":
            return ParameterType.JSON_OBJECT

        # Complex: oneOf, anyOf, allOf, $ref 또는 구조화된 object
        if any(key in schema for key in ("oneOf", "anyOf", "allOf", "$ref")):
            return ParameterType.COMPLEX

        # Array
        if schema_type == "array":
            return ParameterType.ARRAY

        # integer -> Integer
        if schema_type == "integer":
            return ParameterType.INTEGER

        # string + UUID/GUID name
        if schema_type == "string":
            if "uuid" in normalized_name or "guid" in normalized_name:
                return ParameterType.UUID_GUID

            if any(
                keyword in normalized_name
                for keyword in (
                    "email",
                    "phone",
                    "mobile",
                    "telephone",
                    "ssn",
                    "passport",
                )
            ):
                return ParameterType.PERSONAL_INFORMATION

            return ParameterType.STRING

        return ParameterType.OTHER

    # ------------------------------------------------------------------
    # Step 3: Attack vector matching
    # ------------------------------------------------------------------

    def match_dumb_enumeration(
        self,
        endpoint: EndpointInfo,
    ) -> Finding:
        matched_parameters = [
            parameter.name
            for parameter in endpoint.parameters
            if parameter.is_resource_identifier
            and parameter.classified_type == ParameterType.INTEGER
        ]

        matched = (
            endpoint.requires_authentication
            and bool(endpoint.parameters)
            and bool(matched_parameters)
        )

        reason = (
            "authentication required, parameter exists, and resource "
            "identifier has Integer type"
            if matched
            else "condition not satisfied"
        )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="Dumb Enumeration",
            matched=matched,
            reason=reason,
            parameters=matched_parameters,
            severity="High" if matched else "Info",
        )

    def match_a_priori_enumeration(
        self,
        endpoint: EndpointInfo,
    ) -> Finding:
        target_types = {
            ParameterType.UUID_GUID,
            ParameterType.JSON_OBJECT,
            ParameterType.COMPLEX,
            ParameterType.STRING,
        }

        matched_parameters = [
            parameter.name
            for parameter in endpoint.parameters
            if parameter.is_resource_identifier
            and parameter.classified_type in target_types
        ]

        matched = endpoint.requires_authentication and bool(
            matched_parameters
        )

        reason = (
            "authentication required and resource identifier has "
            "UUID/GUID, JSON Object, Complex, or String type"
            if matched
            else "condition not satisfied"
        )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="A priori Enumeration",
            matched=matched,
            reason=reason,
            parameters=matched_parameters,
            severity="High" if matched else "Info",
        )

    def match_list_appending(
        self,
        endpoint: EndpointInfo,
    ) -> Finding:
        matched_parameters = [
            parameter.name
            for parameter in endpoint.parameters
            if parameter.is_resource_identifier
            and parameter.classified_type == ParameterType.ARRAY
        ]

        matched = endpoint.requires_authentication and bool(
            matched_parameters
        )

        reason = (
            "authentication required and resource identifier has Array type"
            if matched
            else "condition not satisfied"
        )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="(JSON) List Appending",
            matched=matched,
            reason=reason,
            parameters=matched_parameters,
            severity="High" if matched else "Info",
        )

    def match_token_manipulation(
        self,
        endpoint: EndpointInfo,
    ) -> Finding:
        matched = endpoint.requires_authentication

        reason = (
            "endpoint declares a security requirement"
            if matched
            else "endpoint has no security requirement"
        )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="Token Manipulation",
            matched=matched,
            reason=reason,
            severity="High" if matched else "Info",
        )

    def match_parameter_pollution(
        self,
        endpoint: EndpointInfo,
    ) -> Finding:
        positions_by_name: Dict[str, Set[str]] = {}

        for parameter in endpoint.parameters:
            normalized_name = self.normalize_name(parameter.name)
            positions_by_name.setdefault(normalized_name, set()).add(
                parameter.location
            )

        polluted_names = [
            name
            for name, locations in positions_by_name.items()
            if len(locations) >= 2
        ]

        matched = endpoint.requires_authentication and bool(polluted_names)

        reason = (
            "same parameter name appears in multiple locations"
            if matched
            else "condition not satisfied"
        )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="Parameter Pollution",
            matched=matched,
            reason=reason,
            parameters=polluted_names,
            severity="High" if matched else "Info",
        )

    def match_verb_tampering(
        self,
        endpoint: EndpointInfo,
        all_endpoints: List[EndpointInfo],
    ) -> Finding:
        same_path_endpoints = [
            item
            for item in all_endpoints
            if item.path == endpoint.path
        ]

        supported_methods = {
            item.method
            for item in same_path_endpoints
        }

        parameter_signatures = {
            item.method: self.parameter_signature(item.parameters)
            for item in same_path_endpoints
        }

        has_multiple_methods = len(supported_methods) >= 2
        has_different_parameter_config = (
            len(set(parameter_signatures.values())) >= 2
        )

        # "전체 HTTP Verb를 허용하지 않는 경우"
        # 일반적으로 모든 표준 HTTP Verb를 지원하지 않는 것을 의미한다고 가정
        does_not_allow_all_verbs = (
            len(supported_methods) >= 2
            and "GET" in supported_methods
            and (
                "PUT" in supported_methods
                or "PATCH" in supported_methods
                or "DELETE" in supported_methods
            )
        )

        matched = (
            has_multiple_methods and has_different_parameter_config
        ) or does_not_allow_all_verbs

        reasons = []

        if has_multiple_methods and has_different_parameter_config:
            reasons.append(
                "multiple methods have different parameter configurations"
            )

        if does_not_allow_all_verbs:
            reasons.append(
                "endpoint does not allow all HTTP verbs"
            )

        return Finding(
            path=endpoint.path,
            method=endpoint.method,
            technique="Verb Tampering",
            matched=matched,
            reason="; ".join(reasons) if matched else "condition not satisfied",
            parameters=[],
            severity="Medium" if matched else "Info",
        )

    # ------------------------------------------------------------------
    # Utility functions
    # ------------------------------------------------------------------

    @staticmethod
    def is_valid_parameter(parameter: Any) -> bool:
        return (
            isinstance(parameter, dict)
            and "name" in parameter
            and "in" in parameter
        )

    @staticmethod
    def normalize_name(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]", "", value).lower()

    @staticmethod
    def tokenize(value: str) -> Set[str]:
        return {
            token.lower()
            for token in re.split(r"[/_.{}\-\s]+", value)
            if token
        }

    @staticmethod
    def extract_path_variables(path: str) -> List[str]:
        return re.findall(r"\{([^}]+)\}", path)

    @classmethod
    def names_are_similar(cls, left: str, right: Optional[str]) -> bool:
        if not right:
            return False

        left_normalized = cls.normalize_name(left)
        right_normalized = cls.normalize_name(right)

        if not left_normalized or not right_normalized:
            return False

        return (
            left_normalized == right_normalized
            or left_normalized in right_normalized
            or right_normalized in left_normalized
        )

    @classmethod
    def closest_path_variable(
        cls,
        parameter_name: str,
        path_variables: List[str],
    ) -> Optional[str]:
        for variable in path_variables:
            if cls.names_are_similar(parameter_name, variable):
                return variable

        return path_variables[0] if path_variables else None

    @staticmethod
    def extract_tags(
        parameter: Dict[str, Any],
        operation: Dict[str, Any],
    ) -> List[str]:
        tags: List[str] = []

        for value in (
            parameter.get("tags", []),
            operation.get("tags", []),
        ):
            if isinstance(value, list):
                tags.extend(str(item) for item in value)

        return tags

    @staticmethod
    def has_security_requirement(operation: Dict[str, Any]) -> bool:
        # OpenAPI operation.security가 []이면 인증 불필요
        if "security" in operation:
            return bool(operation["security"])

        # 전역 security가 없으면 인증 불필요
        # 실제 구현에서는 상위 document 정보를 함께 확인할 수 있음
        return False

    @staticmethod
    def get_supported_methods(path_item: Dict[str, Any]) -> Set[str]:
        return {
            method.upper()
            for method in path_item
            if method.lower() in OpenAPIResourceIDDetector.HTTP_METHODS
        }

    @staticmethod
    def parameter_signature(
        parameters: List[ParameterInfo],
    ) -> Tuple[Tuple[str, str, str], ...]:
        return tuple(
            sorted(
                (
                    parameter.name,
                    parameter.location,
                    parameter.classified_type.value,
                )
                for parameter in parameters
            )
        )


def load_openapi_file(file_path: str) -> Dict[str, Any]:
    import yaml

    with open(file_path, "r", encoding="utf-8") as file:
        if file_path.endswith((".yaml", ".yml")):
            return yaml.safe_load(file)

        return json.load(file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="OpenAPI BOLA/IDOR heuristic detector"
    )
    parser.add_argument("openapi_file")
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output JSON file",
    )

    args = parser.parse_args()

    document = load_openapi_file(args.openapi_file)

    # 전역 security를 operation에 반영
    global_security = document.get("security")

    if global_security:
        for path_item in document.get("paths", {}).values():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if (
                    method.lower()
                    in OpenAPIResourceIDDetector.HTTP_METHODS
                    and "security" not in operation
                ):
                    operation["security"] = global_security

    detector = OpenAPIResourceIDDetector(document)
    result = detector.analyze()

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(output)
    else:
        print(output)
