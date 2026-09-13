from __future__ import annotations

import argparse
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
    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    RESOURCE_ID_WORDS = {
        "name", "filename", "file", "group", "key", "phone", "email",
        "account", "user", "username", "profile", "bucket", "folder",
        "project", "tenant", "organization", "org", "resource", "object", "item",
    }
    ID_NAME_PATTERNS = [
        re.compile(r"^(id|_id)$", re.IGNORECASE),
        re.compile(r".*[_-]?id$", re.IGNORECASE),
        re.compile(r".*[_-]?uuid$", re.IGNORECASE),
        re.compile(r".*[_-]?guid$", re.IGNORECASE),
    ]
    IDENTIFIER_DESCRIPTION_PATTERN = re.compile(
        r"\b(id|uuid|guid|identifier)\b", re.IGNORECASE
    )
    ACTION_VERBS = {
        "add", "create", "edit", "update", "delete", "remove", "modify",
        "change", "reset", "enable", "disable", "activate", "deactivate",
        "verify", "validate", "approve", "reject", "share", "move", "copy", "restore",
    }

    def __init__(self, openapi_document: Dict[str, Any]):
        self.document = openapi_document or {}
        self.paths = self.document.get("paths", {})

    def resolve_reference(self, value: Any) -> Dict[str, Any]:
        """Resolve a local OpenAPI JSON Pointer such as #/components/parameters/UserId."""
        if not isinstance(value, dict):
            return {}
        if "$ref" not in value:
            return value

        ref_value = value.get("$ref")
        if not isinstance(ref_value, str) or not ref_value.startswith("#/"):
            return {}

        current: Any = self.document
        for part in ref_value[2:].split("/"):
            if not isinstance(current, dict):
                return {}
            part = part.replace("~1", "/").replace("~0", "~")
            if part not in current:
                return {}
            current = current[part]
        return current if isinstance(current, dict) else {}

    def analyze(self) -> Dict[str, Any]:
        endpoints = self.extract_endpoints()
        findings = []
        for endpoint in endpoints:
            findings.extend(self.match_attack_vectors(endpoint, endpoints))
        return {
            "openapi_version": self.document.get("openapi"),
            "endpoints": [self.endpoint_to_dict(e) for e in endpoints],
            "findings": [f.to_dict() for f in findings],
        }

    @staticmethod
    def endpoint_to_dict(endpoint: EndpointInfo) -> Dict[str, Any]:
        return {
            "path": endpoint.path,
            "method": endpoint.method,
            "requires_authentication": endpoint.requires_authentication,
            "parameters": [
                {
                    "name": p.name, "location": p.location, "required": p.required,
                    "is_resource_identifier": p.is_resource_identifier,
                    "resource_id_reasons": p.resource_id_reasons,
                    "classified_type": p.classified_type.value,
                }
                for p in endpoint.parameters
            ],
        }

    def extract_endpoints(self) -> List[EndpointInfo]:
        endpoints = []
        for path, path_item in self.paths.items():
            if not isinstance(path_item, dict):
                continue
            path_params = path_item.get("parameters", [])
            for method, operation in path_item.items():
                method_lower = str(method).lower()
                if method_lower not in self.HTTP_METHODS or not isinstance(operation, dict):
                    continue
                raw_params = path_params + operation.get("parameters", [])
                parameters = []
                for raw in raw_params:
                    parameter = self.resolve_reference(raw)
                    if self.is_valid_parameter(parameter):
                        parameters.append(self.build_parameter_info(parameter, path, operation))
                endpoints.append(EndpointInfo(
                    path=path, method=method_lower.upper(), operation=operation,
                    parameters=parameters,
                    requires_authentication=self.has_security_requirement(operation),
                    supported_methods=self.get_supported_methods(path_item),
                ))
        return endpoints

    def build_parameter_info(self, parameter: Dict[str, Any], path: str, operation: Dict[str, Any]) -> ParameterInfo:
        parameter = self.resolve_reference(parameter)
        name = str(parameter.get("name", ""))
        location = str(parameter.get("in", "")).lower()
        schema = parameter.get("schema", {})
        if not isinstance(schema, dict):
            schema = {}
        description = str(parameter.get("description") or schema.get("description") or "")
        tags = self.extract_tags(parameter, operation)
        is_id, reasons = self.is_resource_identifier(name, path, description, tags, schema, parameter)
        return ParameterInfo(
            name=name, location=location, required=bool(parameter.get("required", False)),
            schema=schema, description=description, tags=tags,
            is_resource_identifier=is_id, resource_id_reasons=reasons,
            classified_type=self.classify_parameter_type(name, schema),
        )

    def is_resource_identifier(self, name: str, path: str, description: str, tags: List[str], schema: Dict[str, Any], parameter: Dict[str, Any]) -> Tuple[bool, List[str]]:
        reasons = []
        normalized = self.normalize_name(name)
        if any(p.match(name) for p in self.ID_NAME_PATTERNS):
            reasons.append("parameter name matches ID/UUID/GUID rule")
        if normalized in {self.normalize_name(x) for x in self.RESOURCE_ID_WORDS}:
            reasons.append("parameter name matches predefined identifier word")
        variables = self.extract_path_variables(path)
        if any(self.names_are_similar(name, v) for v in variables):
            reasons.append("parameter name is similar to path variable")
        if self.ACTION_VERBS.intersection(self.tokenize(path)) and any(self.names_are_similar(name, v) for v in variables):
            reasons.append("action verb exists in path and parameter references path resource")
        if self.IDENTIFIER_DESCRIPTION_PATTERN.search(" ".join([description, *tags, str(schema.get("description", ""))])):
            reasons.append("description or tag contains ID/UUID/GUID/identifier")
        if parameter.get("x-resource-id") is True or schema.get("x-resource-id") is True:
            reasons.append("explicit x-resource-id marker")
        return bool(reasons), reasons

    def classify_parameter_type(self, name: str, schema: Dict[str, Any]) -> ParameterType:
        schema_type = schema.get("type")
        normalized = self.normalize_name(name)
        if schema_type == "object":
            return ParameterType.JSON_OBJECT
        if any(k in schema for k in ("oneOf", "anyOf", "allOf", "$ref")):
            return ParameterType.COMPLEX
        if schema_type == "array":
            return ParameterType.ARRAY
        if schema_type == "integer":
            return ParameterType.INTEGER
        if schema_type == "string":
            if "uuid" in normalized or "guid" in normalized:
                return ParameterType.UUID_GUID
            if any(x in normalized for x in ("email", "phone", "mobile", "telephone", "ssn", "passport")):
                return ParameterType.PERSONAL_INFORMATION
            return ParameterType.STRING
        return ParameterType.OTHER

    def match_attack_vectors(self, endpoint: EndpointInfo, all_endpoints: List[EndpointInfo]) -> List[Finding]:
        return [
            self.match_dumb_enumeration(endpoint),
            self.match_a_priori_enumeration(endpoint),
            self.match_list_appending(endpoint),
            self.match_token_manipulation(endpoint),
            self.match_parameter_pollution(endpoint),
            self.match_verb_tampering(endpoint, all_endpoints),
        ]

    def match_dumb_enumeration(self, e: EndpointInfo) -> Finding:
        params = [p.name for p in e.parameters if p.is_resource_identifier and p.classified_type == ParameterType.INTEGER]
        matched = e.requires_authentication and bool(e.parameters) and bool(params)
        return Finding(e.path, e.method, "Dumb Enumeration", matched, "authentication required, parameter exists, and resource identifier has Integer type" if matched else "condition not satisfied", params, "High" if matched else "Info")

    def match_a_priori_enumeration(self, e: EndpointInfo) -> Finding:
        targets = {ParameterType.UUID_GUID, ParameterType.JSON_OBJECT, ParameterType.COMPLEX, ParameterType.STRING}
        params = [p.name for p in e.parameters if p.is_resource_identifier and p.classified_type in targets]
        matched = e.requires_authentication and bool(params)
        return Finding(e.path, e.method, "A priori Enumeration", matched, "authentication required and resource identifier has UUID/GUID, JSON Object, Complex, or String type" if matched else "condition not satisfied", params, "High" if matched else "Info")

    def match_list_appending(self, e: EndpointInfo) -> Finding:
        params = [p.name for p in e.parameters if p.is_resource_identifier and p.classified_type == ParameterType.ARRAY]
        matched = e.requires_authentication and bool(params)
        return Finding(e.path, e.method, "(JSON) List Appending", matched, "authentication required and resource identifier has Array type" if matched else "condition not satisfied", params, "High" if matched else "Info")

    def match_token_manipulation(self, e: EndpointInfo) -> Finding:
        matched = e.requires_authentication
        return Finding(e.path, e.method, "Token Manipulation", matched, "endpoint declares a security requirement" if matched else "endpoint has no security requirement", [], "High" if matched else "Info")

    def match_parameter_pollution(self, e: EndpointInfo) -> Finding:
        locations: Dict[str, Set[str]] = {}
        for p in e.parameters:
            locations.setdefault(self.normalize_name(p.name), set()).add(p.location)
        names = [n for n, locs in locations.items() if len(locs) >= 2]
        matched = e.requires_authentication and bool(names)
        return Finding(e.path, e.method, "Parameter Pollution", matched, "same parameter name appears in multiple locations" if matched else "condition not satisfied", names, "High" if matched else "Info")

    def match_verb_tampering(self, e: EndpointInfo, all_endpoints: List[EndpointInfo]) -> Finding:
        same = [x for x in all_endpoints if x.path == e.path]
        methods = {x.method for x in same}
        signatures = {x.method: self.parameter_signature(x.parameters) for x in same}
        multiple = len(methods) >= 2
        different = len(set(signatures.values())) >= 2
        limited = len(methods) >= 2 and "GET" in methods and bool(methods & {"PUT", "PATCH", "DELETE"})
        matched = (multiple and different) or limited
        reasons = []
        if multiple and different:
            reasons.append("multiple methods have different parameter configurations")
        if limited:
            reasons.append("endpoint does not allow all HTTP verbs")
        return Finding(e.path, e.method, "Verb Tampering", matched, "; ".join(reasons) if matched else "condition not satisfied", [], "Medium" if matched else "Info")

    @staticmethod
    def is_valid_parameter(parameter: Any) -> bool:
        return isinstance(parameter, dict) and "name" in parameter and "in" in parameter

    @staticmethod
    def normalize_name(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]", "", str(value)).lower()

    @staticmethod
    def tokenize(value: str) -> Set[str]:
        return {x.lower() for x in re.split(r"[/_.{}\-\s]+", value) if x}

    @staticmethod
    def extract_path_variables(path: str) -> List[str]:
        return re.findall(r"\{([^}]+)\}", path)

    @classmethod
    def names_are_similar(cls, left: str, right: Optional[str]) -> bool:
        if not right:
            return False
        a, b = cls.normalize_name(left), cls.normalize_name(right)
        return bool(a and b and (a == b or a in b or b in a))

    @staticmethod
    def extract_tags(parameter: Dict[str, Any], operation: Dict[str, Any]) -> List[str]:
        result = []
        for value in (parameter.get("tags", []), operation.get("tags", [])):
            if isinstance(value, list):
                result.extend(str(x) for x in value)
        return result

    def has_security_requirement(self, operation: Dict[str, Any]) -> bool:
        if "security" in operation:
            return bool(operation["security"])
        return bool(self.document.get("security"))

    @classmethod
    def get_supported_methods(cls, path_item: Dict[str, Any]) -> Set[str]:
        return {str(m).upper() for m in path_item if str(m).lower() in cls.HTTP_METHODS}

    @staticmethod
    def parameter_signature(parameters: List[ParameterInfo]) -> Tuple[Tuple[str, str, str], ...]:
        return tuple(sorted((p.name, p.location, p.classified_type.value) for p in parameters))


def load_openapi_file(file_path: str) -> Dict[str, Any]:
    import yaml
    with open(file_path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) if file_path.lower().endswith((".yaml", ".yml")) else json.load(file)
    if not isinstance(data, dict):
        raise ValueError("OpenAPI 문서의 최상위 값은 객체여야 합니다.")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAPI BOLA/IDOR heuristic detector")
    parser.add_argument("openapi_file")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    document = load_openapi_file(args.openapi_file)
    result = OpenAPIResourceIDDetector(document).analyze()
    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
