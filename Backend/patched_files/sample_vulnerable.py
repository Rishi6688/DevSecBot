import subprocess

def check_host(host):
    print("Checking host...")
    subprocess.run(["ping", host], shell=False)
    print("Check completed.")
