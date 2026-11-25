
from pathlib import Path
from patcher import apply_patch

original = Path("sample_vulnerable.py")

original_code = '''import subprocess

def check_host(host):
    print("Checking host...")
    subprocess.run(f"ping {host}", shell=True)
    print("Check completed.")
'''

original.write_text(original_code, encoding="utf-8")

vulnerable_code = 'subprocess.run(f"ping {host}", shell=True)'

fixed_code = 'subprocess.run(["ping", host], shell=False)'

result = apply_patch(
    str(original),
    vulnerable_code,
    fixed_code
)

print(result)

print("\nOriginal file:")
print(original.read_text(encoding="utf-8"))

if result["status"] == "success":
    patched = Path(result["patched_file"])

    print("\nPatched file:")
    print(patched.read_text(encoding="utf-8"))


# Test: Reject code that does not exist in the original file.
result = apply_patch(
    str(original),
    "subprocess.run('unknown command')",
    'subprocess.run(["safe"], shell=False)'
)

print("\nMissing vulnerable code test:")
print(result)
