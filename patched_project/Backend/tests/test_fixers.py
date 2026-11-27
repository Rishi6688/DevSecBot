
from fixers.command_injection import build_command_injection_fix


def test_simple_ping_command():
    code = 'subprocess.run(f"ping {host}", shell=True)'

    fixed_code = build_command_injection_fix(code)

    assert fixed_code is not None
    assert "shell=False" in fixed_code
    assert "host" in fixed_code


def test_simple_grep_command():
    code = 'subprocess.run(f"grep {pattern} {filename}", shell=True)'

    fixed_code = build_command_injection_fix(code)

    assert fixed_code is not None
    assert "shell=False" in fixed_code


def test_chained_command_is_rejected():
    code = 'subprocess.run(f"ping {host} && dir", shell=True)'

    fixed_code = build_command_injection_fix(code)

    assert fixed_code is None
