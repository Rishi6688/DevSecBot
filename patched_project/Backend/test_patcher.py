
from pathlib import Path
from patcher import apply_patch

# Create a temporary vulnerable Python file
original = Path("patcher_test_input.py")

original_code = '''import subprocess

def check_host(host):
    print("Checking host...")
    subprocess.run(f"ping {host}", shell=True)
    print("Check completed.")
'''

original.write_text(original_code, encoding="utf-8")

vulnerable_code = 'subprocess.run(f"ping {host}", shell=True)'
fixed_code = 'subprocess.run(["ping", host], shell=False)'

# Test 1: Successful patch creation
result = apply_patch(
    str(original),
    vulnerable_code,
    fixed_code
)

print("\nPATCH CREATION TEST:")
print(result)

# Check whether patch creation and local validation succeeded
if result["status"] == "awaiting_semgrep_validation":

    patched = Path(result["patched_file"])

    print("\nPatched file:")
    print(patched.read_text(encoding="utf-8"))

    print("\nOriginal file unchanged:")
    print(original.read_text(encoding="utf-8") == original_code)

else:
    print("Patch creation failed.")

# Test 2: Original file must remain unchanged
print("\nORIGINAL FILE PRESERVATION TEST:")
print(original.read_text(encoding="utf-8") == original_code)

# Test 3: Reject vulnerable code that does not exist
result = apply_patch(
    str(original),
    "subprocess.run('unknown command')",
    'subprocess.run(["safe"], shell=False)'
)

print("\nMISSING VULNERABLE CODE TEST:")
print(result)
