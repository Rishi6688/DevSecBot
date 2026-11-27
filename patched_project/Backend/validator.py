
import ast
import subprocess
import sys
from pathlib import Path


def validate_patched_file(file_path: str):

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

    # Step 1: Python syntax validation
    try:
        source_code = path.read_text(encoding="utf-8")
        ast.parse(source_code)

    except (SyntaxError, OSError) as error:
        return {
            "status": "failed",
            "syntax_check": "failed",
            "message": str(error)
        }

    # Step 2: Compile validation
    try:
        subprocess.run(
            [sys.executable, "-m", "py_compile", str(path)],
            capture_output=True,
            text=True,
            check=True
        )

    except subprocess.CalledProcessError as error:
        return {
            "status": "failed",
            "syntax_check": "failed",
            "message": error.stderr
        }

    return {
        "status": "passed",
        "syntax_check": "passed",
        "semgrep_check": "pending_github_actions",
        "message": "Python validation passed. Semgrep verification must run through GitHub Actions."
    }

