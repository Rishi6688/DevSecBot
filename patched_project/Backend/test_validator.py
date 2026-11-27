
from validator import validate_patched_file

result = validate_patched_file(
    "patched_files/sample_vulnerable.py"
)

print("VALIDATION RESULT:")
print(result)
