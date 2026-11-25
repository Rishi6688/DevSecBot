
from pathlib import Path
import ast


def apply_patch(original_file: str, vulnerable_code: str, fixed_code: str):
    """
    Replace only the vulnerable code in a Python file.
    Save the modified file separately.
    Preserve the original file.
    """

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
        # Read the complete original file.
        original_content = source_path.read_text(encoding="utf-8")

        # Ensure the vulnerable code occurs exactly once.
        occurrences = original_content.count(vulnerable_code)

        if occurrences != 1:
            return {
                "status": "failed",
                "message": (
                    f"Expected one occurrence of vulnerable code, "
                    f"but found {occurrences}."
                )
            }

        # Replace only the vulnerable section.
        patched_content = original_content.replace(
            vulnerable_code,
            fixed_code,
            1
        )

        # Validate the complete modified Python file.
        ast.parse(patched_content)

        # Save the result separately.
        output_dir = source_path.parent / "patched_files"
        output_dir.mkdir(exist_ok=True)

        output_path = output_dir / source_path.name

        output_path.write_text(
            patched_content,
            encoding="utf-8"
        )

        return {
            "status": "success",
            "original_file": str(source_path),
            "patched_file": str(output_path),
            "message": "Vulnerable code replaced successfully."
        }

    except SyntaxError as error:
        return {
            "status": "failed",
            "message": f"Invalid Python syntax: {error}"
        }

    except OSError as error:
        return {
            "status": "failed",
            "message": str(error)
        }
