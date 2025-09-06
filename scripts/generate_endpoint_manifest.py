#!/usr/bin/env python3
import os
import re
import json
from typing import List, Dict, Any, Tuple


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


ROUTE_REGEX = re.compile(r"\.route\(\s*\"([^\"]+)\"\s*,\s*([^\)]*)\)")
METHOD_REGEXES = {
    "GET": re.compile(r"\bget\s*\(\s*"),
    "POST": re.compile(r"\bpost\s*\(\s*"),
    "PUT": re.compile(r"\bput\s*\(\s*"),
    "DELETE": re.compile(r"\bdelete\s*\(\s*"),
    "PATCH": re.compile(r"\bpatch\s*\(\s*"),
    "OPTIONS": re.compile(r"\boptions\s*\(\s*"),
}


def walk_rs_files(base_dir: str) -> List[str]:
    paths: List[str] = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".rs"):
                paths.append(os.path.join(root, f))
    return paths


def parse_routes_from_file(path: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except Exception:
        return results

    for m in ROUTE_REGEX.finditer(content):
        route_path = m.group(1)
        inner = m.group(2)
        # Extract potentially multiple methods from chained builder (e.g., post(...).get(...))
        found_any = False
        for method, rx in METHOD_REGEXES.items():
            if rx.search(inner):
                results.append((method, route_path))
                found_any = True
        if not found_any:
            # Could be something like get(handler) written as axum::routing::get(...)
            lowered = inner.lower()
            for method in ["get", "post", "put", "delete", "patch", "options"]:
                if method in lowered:
                    results.append((method.upper(), route_path))
    return results


def collect_code_endpoints() -> List[Dict[str, Any]]:
    services = [
        ("auth-service", os.path.join(ROOT, "auth-service", "src")),
        ("policy-service", os.path.join(ROOT, "enterprise", "policy-service", "src")),
    ]
    endpoints: List[Dict[str, Any]] = []
    for service, base in services:
        if not os.path.isdir(base):
            continue
        for path in walk_rs_files(base):
            for method, route in parse_routes_from_file(path):
                endpoints.append({
                    "service": service,
                    "source": "code",
                    "method": method,
                    "path": route,
                    "file": os.path.relpath(path, ROOT),
                })
    return endpoints


def collect_openapi_endpoints() -> List[Dict[str, Any]]:
    openapi_dir = os.path.join(ROOT, "api-specs")
    if not os.path.isdir(openapi_dir):
        return []
    endpoints: List[Dict[str, Any]] = []
    # very lightweight YAML-ish parsing; avoids requiring PyYAML
    for name in os.listdir(openapi_dir):
        if not name.endswith(".yaml") and not name.endswith(".yml"):
            continue
        path = os.path.join(openapi_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except Exception:
            continue
        in_paths = False
        current_path = None
        service = "auth-service" if "auth" in name else ("policy-service" if "policy" in name else "unknown")
        for raw in lines:
            line = raw.rstrip("\n")
            if line.strip().startswith("paths:"):
                in_paths = True
                current_path = None
                continue
            if not in_paths:
                continue
            # Detect a new path line (e.g., two spaces then /path:)
            if re.match(r"^\s{2}/[^:]+:\s*$", line):
                current_path = line.strip()[:-1]  # remove trailing colon
                continue
            # Detect method lines under a path (e.g., four spaces then get:)
            m = re.match(r"^\s{4}([a-zA-Z]+):\s*$", line)
            if current_path and m:
                method = m.group(1).upper()
                # Only include standard HTTP verbs
                if method in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
                    endpoints.append({
                        "service": service,
                        "source": "openapi",
                        "method": method,
                        "path": current_path,
                        "file": os.path.relpath(path, ROOT),
                    })
            # End of paths block heuristic: a top-level non-indented key
            if re.match(r"^[^\s][^:]*:\s*$", line):
                if current_path is not None:
                    # leaving paths
                    in_paths = False
                    current_path = None
    return endpoints


def dedupe_endpoints(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in items:
        key = (item["service"], item["method"], item["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    out.sort(key=lambda x: (x["service"], x["path"], x["method"]))
    return out


def main() -> None:
    code_eps = collect_code_endpoints()
    spec_eps = collect_openapi_endpoints()
    merged = dedupe_endpoints(code_eps + spec_eps)
    out_dir = os.path.join(ROOT, "api-specs")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "endpoint-manifest.generated.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "endpoints": merged,
            "notes": "Sources include router code and OpenAPI specs; verify bases for nested routers.",
        }, fh, indent=2)
    print(f"Wrote {out_path} with {len(merged)} unique endpoints")


if __name__ == "__main__":
    main()

