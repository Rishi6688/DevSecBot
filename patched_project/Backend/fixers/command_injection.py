

import re
import shlex


def build_command_injection_fix(code: str):
    """
    Converts supported subprocess.run() f-string commands
    with shell=True into argument-list commands with shell=False.

    Supports different executables and multiple arguments.
    Returns None for unsupported or unsafe patterns.
    """

    pattern = re.compile(
        r"""subprocess\.run\(\s*f(["'])(.*?)\1\s*,\s*shell\s*=\s*True\s*\)""",
        re.DOTALL
    )

    match = pattern.search(code)

    if not match:
        return None

    command_template = match.group(2)

    # Reject shell-specific syntax that needs manual handling.
    dangerous_symbols = ["|", ";", "&", ">", "<", "`", "$", "\n", "\r"]

    if any(symbol in command_template for symbol in dangerous_symbols):
        return None

    # Find simple variable placeholders.
    placeholders = re.findall(
        r"\{([a-zA-Z_]\w*)\}",
        command_template
    )

    if not placeholders:
        return None

    # Replace each variable with a unique temporary token.
    token_to_variable = {}

    def replace_placeholder(match):
        variable = match.group(1)
        token = f"DEVSECBOTVAR{len(token_to_variable)}"
        token_to_variable[token] = variable
        return token

    temporary_command = re.sub(
        r"\{([a-zA-Z_]\w*)\}",
        replace_placeholder,
        command_template
    )

    # Reject unsupported expressions or unmatched braces.
    if "{" in temporary_command or "}" in temporary_command:
        return None

    try:
        command_parts = shlex.split(temporary_command)
    except ValueError:
        return None

    if not command_parts:
        return None

    arguments = []

    for part in command_parts:
        if part in token_to_variable:
            arguments.append(token_to_variable[part])
        elif any(token in part for token in token_to_variable):
            # Do not guess how to split combined arguments.
            return None
        else:
            arguments.append(repr(part))

    fixed_code = (
        "subprocess.run("
        "[" + ", ".join(arguments) + "], "
        "shell=False)"
    )

    return fixed_code
