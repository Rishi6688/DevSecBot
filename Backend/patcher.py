from pathlib import Path
from validator import validate_patched_file


def apply_patch(original_file: str, vulnerable_code: str, fixed_code: str):

    source_path = Path(original_file)

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
        original_content = source_path.read_text(encoding="utf-8")

        occurrences = original_content.count(vulnerable_code)

        if occurrences != 1:
            return {
                "status": "failed",
                "message": (
                    f"Expected exactly one occurrence, "
                    f"but found {occurrences}."
                )
            }

        patched_content = original_content.replace(
            vulnerable_code,
            fixed_code,
            1
        )

        output_dir = source_path.parent / "patched_files"
        output_dir.mkdir(exist_ok=True)

        output_path = output_dir / source_path.name

        output_path.write_text(
            patched_content,
            encoding="utf-8"
        )

        validation = validate_patched_file(str(output_path))

        if validation["status"] != "passed":
            output_path.unlink(missing_ok=True)

            return {
                "status": "failed",
                "validation": validation,
                "message": "Patched file failed local validation."
            }

        return {
            "status": "awaiting_semgrep_validation",
            "original_file": str(source_path),
            "patched_file": str(output_path),
            "validation": validation,
            "message": (
                "Patch created and local validation passed. "
                "GitHub Actions Semgrep verification is still required."
            )
        }

    except OSError as error:
        return {
            "status": "failed",
            "message": str(error)
        }
    