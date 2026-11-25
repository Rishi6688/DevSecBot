
import ast
import json
import subprocess
import sys
from pathlib import Path

def validate_patched_file(file_path: str, original_check_id: str = None):

    path = Path(file_path)

    if not path.exists():
        return {
            "status": "failed",
            "message": "Patched file not found."
        }

    if path.suffix != ".py":
        return {
            "status": "failed",
            "message": "Only Python files are supported."
        }

    # Step 1: Check Python syntax
    try:
        source_code = path.read_text(encoding="utf-8")
        ast.parse(source_code)

    except (SyntaxError, OSError) as error:
        return {
            "status": "failed",
            "syntax_check": "failed",
            "message": str(error)
        }

    # Step 2: Run Semgrep scan
    command = [
        sys.executable,
        "-m",
        "semgrep",
        "scan",
        "--config",
        "p/security-audit",
        "--json",
        str(path)
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode not in (0, 1):
            return {
                "status": "failed",
                "syntax_check": "passed",
                "semgrep_check": "error",
                "message": result.stderr
            }

        scan_data = json.loads(result.stdout)

        findings = scan_data.get("results", [])

        if original_check_id:
            remaining = [
                finding for finding in findings
                if finding.get("check_id") == original_check_id
            ]
        else:
            remaining = findings

        if remaining:
            return {
                "status": "failed",
                "syntax_check": "passed",
                "semgrep_check": "failed",
                "remaining_findings": remaining,
                "message": "Security findings remain."
            }

        return {
            "status": "passed",
            "syntax_check": "passed",
            "semgrep_check": "passed",
            "message": "No matching Semgrep findings detected."
        }

    except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        return {
            "status": "failed",
            "syntax_check": "passed",
            "semgrep_check": "error",
            "message": str(error)
        }