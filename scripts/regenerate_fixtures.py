#!/usr/bin/env python3
"""Regenerate results.xml fixture files by running codacy-trivy Docker image."""

import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs/multiple-tests"
IMAGE = "codacy-trivy:latest"


def parse_patterns_xml(patterns_file: Path) -> list[str]:
    tree = ET.parse(patterns_file)
    root = tree.getroot()
    return [m.get("name") for m in root.findall(".//module[@name]") if m.get("name") != "root"]


def list_files(src_dir: Path) -> list[str]:
    files = []
    for p in sorted(src_dir.rglob("*")):
        if p.is_file():
            files.append(p.relative_to(src_dir).as_posix())
    return files


def run_tool(src_dir: Path, patterns: list[str]) -> list[dict]:
    codacyrc = {
        "files": list_files(src_dir),
        "tools": [{
            "name": "trivy",
            "patterns": [{"patternId": pid, "parameters": []} for pid in patterns]
        }]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".codacyrc", delete=False) as f:
        json.dump(codacyrc, f)
        f.flush()
        rc_path = f.name

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{src_dir.resolve()}:/src:ro",
                "-v", f"{rc_path}:/.codacyrc:ro",
                IMAGE
            ],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0 and not result.stdout.strip():
            print(f"  ERROR: docker run failed: {result.stderr[:200]}", file=sys.stderr)
            return []

        issues = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Skip SBOM output
                if "bomFormat" in obj:
                    continue
                if "filename" in obj:
                    issues.append(obj)
            except json.JSONDecodeError:
                pass
        return issues
    finally:
        os.unlink(rc_path)


# Maps patternId to checkstyle severity (based on patterns.json level field)
PATTERN_SEVERITY = {
    "vulnerability_critical": "error",
    "vulnerability_high": "high",
    "vulnerability_medium": "warning",
    "vulnerability_minor": "info",
    "secret": "error",
    "malicious_packages": "error",
}


def escape_xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def write_results_xml(issues: list[dict], output_file: Path):
    # Group by filename
    by_file: dict[str, list[dict]] = {}
    for issue in issues:
        fname = issue["filename"]
        by_file.setdefault(fname, []).append(issue)

    lines = ['<?xml version="1.0" encoding="utf-8"?>', '<checkstyle version="1.5">']
    for fname in sorted(by_file):
        lines.append(f'    <file name="{escape_xml(fname)}">')
        file_issues = sorted(by_file[fname], key=lambda x: (x.get("line", 0), x.get("message", "")))
        for issue in file_issues:
            line = str(issue.get("line", 1))
            message = escape_xml(issue.get("message", ""))
            pattern_id = issue.get("patternId", "")
            severity = PATTERN_SEVERITY.get(pattern_id, "warning")
            lines.append('        <error')
            lines.append(f'            source="{pattern_id}"')
            lines.append(f'            line="{line}"')
            lines.append(f'            message="{message}"')
            lines.append(f'            severity="{severity}"')
            lines.append('        />')
        lines.append('    </file>')
    lines.append('</checkstyle>')

    output_file.write_text("\n".join(lines) + "\n")


def main():
    test_dirs = sorted(DOCS_DIR.iterdir())
    for test_dir in test_dirs:
        if not test_dir.is_dir():
            continue
        patterns_file = test_dir / "patterns.xml"
        src_dir = test_dir / "src"
        results_file = test_dir / "results.xml"

        if not patterns_file.exists() or not src_dir.exists():
            continue

        patterns = parse_patterns_xml(patterns_file)
        print(f"Running {test_dir.name} with patterns: {patterns}")

        issues = run_tool(src_dir, patterns)
        print(f"  Found {len(issues)} issues")

        write_results_xml(issues, results_file)
        print(f"  Written {results_file}")


if __name__ == "__main__":
    main()
