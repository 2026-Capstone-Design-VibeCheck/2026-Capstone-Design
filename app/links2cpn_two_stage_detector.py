from __future__ import annotations

"""Two-stage BOLA/IDOR detector.

Stage 1: bola_idor_detector.OpenAPIResourceIDDetector
Stage 2: ailton07/openapi-links-to-CPNs (Links2CPN) replay/conformance check.

Links2CPN does not send HTTP requests. It replays an existing event-log file
against the CPN generated from OpenAPI links.
"""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from bola_idor_detector import (
    OpenAPIResourceIDDetector,
    load_openapi_file,
)


HTTP_LINE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+([1-5]\d\d)(?:\s+(.*))?$",
    re.IGNORECASE,
)
NOT_IN_MODEL = "not present in the model"


def run_links2cpn(
    repository: str,
    openapi_file: str,
    event_log: str,
    python_executable: str | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run the official repository entry point: src/execute_replay.py."""
    repo = Path(repository).resolve()
    script = repo / "src" / "execute_replay.py"
    if not script.is_file():
        raise FileNotFoundError(f"Links2CPN entry point not found: {script}")

    py = python_executable or shutil.which("python3") or shutil.which("python")
    if not py:
        raise RuntimeError("Python executable was not found")

    command = [py, str(script), str(Path(openapi_file).resolve()), str(Path(event_log).resolve())]
    try:
        completed = subprocess.run(
            command, cwd=str(repo / "src"), capture_output=True,
            text=True, timeout=timeout, check=False,
        )
        stdout, stderr = completed.stdout or "", completed.stderr or ""
        return {
            "success": completed.returncode == 0,
            "return_code": completed.returncode,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "replay_events": parse_replay_output(stdout + "\n" + stderr),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False, "timeout": True, "return_code": None,
            "command": command, "stdout": exc.stdout or "",
            "stderr": exc.stderr or "", "replay_events": [],
        }


def parse_replay_output(text: str) -> list[dict[str, Any]]:
    """Parse Lines2CPN console lines such as:
       Line 1 is not present in the model: GET /api/items/1 200 9ms
    """
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = HTTP_LINE.search(line.strip())
        if not match:
            continue
        method, path, status, latency = match.groups()
        events.append({
            "line": line_number,
            "method": method.upper(),
            "path": path,
            "status_code": int(status),
            "latency": latency or "",
            "present_in_model": NOT_IN_MODEL not in line.lower(),
            "raw": line.strip(),
        })
    return events


def endpoint_matches(template: str, observed: str) -> bool:
    """Match /items/{itemId} against /items/123, including query removal."""
    template = template.split("?", 1)[0].rstrip("/")
    observed = observed.split("?", 1)[0].rstrip("/")
    left, right = template.strip("/").split("/"), observed.strip("/").split("/")
    if len(left) != len(right):
        return False
    return all(a.startswith("{") and a.endswith("}") or a.lower() == b.lower()
               for a, b in zip(left, right))


def attach_dynamic_evidence(
    static_result: dict[str, Any],
    links_result: dict[str, Any],
) -> dict[str, Any]:
    """Attach replay evidence to each Stage-1 finding.

    'confirmed' means the observed event was represented by the OpenAPI-links
    CPN. It does NOT by itself prove a broken authorization check/IDOR.
    """
    events = links_result.get("replay_events", [])
    findings = []
    for original in static_result.get("findings", []):
        finding = dict(original)
        matched = [
            event for event in events
            if event["method"] == finding["method"].upper()
            and endpoint_matches(finding["path"], event["path"])
        ]
        finding["links2cpn_evidence"] = matched
        finding["dynamic_verified"] = any(e["present_in_model"] for e in matched)
        finding["dynamic_status"] = (
            "confirmed-flow" if finding["dynamic_verified"] else
            "observed-not-in-cpn" if matched else "not-replayed"
        )
        finding["final_status"] = (
            "candidate-with-confirmed-flow"
            if finding["matched"] and finding["dynamic_verified"]
            else "candidate-static-only"
            if finding["matched"] else "not-matched"
        )
        findings.append(finding)

    return {**static_result, "links2cpn": links_result, "findings": findings}


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    document = load_openapi_file(args.openapi_file)
    # Apply OpenAPI global security exactly as the original detector's CLI does.
    global_security = document.get("security")
    if global_security:
        for path_item in document.get("paths", {}).values():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if (method.lower() in OpenAPIResourceIDDetector.HTTP_METHODS
                        and isinstance(operation, dict)
                        and "security" not in operation):
                    operation["security"] = global_security

    stage1 = OpenAPIResourceIDDetector(document).analyze()
    stage2 = run_links2cpn(
        repository=args.links2cpn_repo,
        openapi_file=args.openapi_file,
        event_log=args.event_log,
        python_executable=args.links2cpn_python,
        timeout=args.timeout,
    )
    return attach_dynamic_evidence(stage1, stage2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Two-stage OpenAPI BOLA/IDOR detector")
    parser.add_argument("openapi_file", help="OpenAPI YAML/JSON")
    parser.add_argument("--event-log", required=True, help="Links2CPN event log")
    parser.add_argument("--links2cpn-repo", required=True, help="Cloned Links2CPN directory")
    parser.add_argument("--links2cpn-python", default=None, help="Links2CPN venv Python")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--output", default="two-stage-result.json")
    args = parser.parse_args()

    result = analyze(args)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
