
import shutil
from pathlib import Path

from validator import validate_patched_file

def apply_patch(
    original_file: str,
    vulnerable_code: str,
    fixed_code: str,
    project_root: str
):
    source_path = Path(original_file).resolve()
    root_path = Path(project_root).resolve()

    if not source_path.exists():
        return {
            "status": "failed",
            "message": "Original file not found."
        }

    if source_path.suffix != ".py":
        return {
            "status": "failed",
            "message": "Only Python files are supported."
        }

    if not vulnerable_code or not fixed_code:
        return {
            "status": "failed",
            "message": "Vulnerable code or fixed code is missing."
        }

    try:
        # Ensure the source file belongs to the project
        relative_path = source_path.relative_to(root_path)

        if not source_path.is_file():
            raise ValueError("Source path is not a file.")

        original_content = source_path.read_text(encoding="utf-8")

        # Ensure the vulnerable code occurs exactly once
        occurrences = original_content.count(vulnerable_code)

        if occurrences != 1:
            return {
                "status": "failed",
                "message": (
                    f"Expected exactly one occurrence, "
                    f"but found {occurrences}."
                )
            }

        # Generate patched content
        patched_content = original_content.replace(
            vulnerable_code,
            fixed_code,
            1
        )

        # Create patched project inside the original project
        output_root = root_path / "patched_project"

        if output_root.exists():
            shutil.rmtree(output_root)

        # Exclude unnecessary and generated files
        ignored = shutil.ignore_patterns(
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            "*.pyc",
            ".env",
            "patched_files",
            "patched_projects",
            "patched_project"
        )

        # Copy the complete project
        shutil.copytree(
            root_path,
            output_root,
            ignore=ignored
        )

        # Apply the fix inside the copied project
        output_path = output_root / relative_path

        output_path.write_text(
            patched_content,
            encoding="utf-8"
        )

        # Validate the patched Python file
        validation = validate_patched_file(str(output_path))

        if validation["status"] != "passed":
            shutil.rmtree(output_root, ignore_errors=True)

            return {
                "status": "failed",
                "validation": validation,
                "message": "Patched file failed local validation."
            }

        return {
            "status": "awaiting_semgrep_validation",
            "original_file": str(source_path),
            "patched_file": str(output_path),
            "patched_project": str(output_root),
            "validation": validation,
            "message": (
                "Full project copy created inside the repository. "
                "Patch applied and local validation passed. "
                "Full-project Semgrep verification is still required."
            )
        }

    except (OSError, ValueError) as error:
        return {
            "status": "failed",
            "message": str(error)
        }