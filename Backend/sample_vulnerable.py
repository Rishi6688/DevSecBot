import subprocess

def check_host(host):
    print("Checking host...")
    subprocess.run(f"ping {host}", shell=True)
    print("Check completed.")
