# Example vulnerable Python file for testing

import subprocess
import os

# CRITICAL: Hardcoded API key
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "token_xyz_12345"

# HIGH: Using eval with user input
def process_user_input(user_input):
    result = eval(user_input)
    return result

# HIGH: Using exec
def run_dynamic_code(code):
    exec(code)

# HIGH: subprocess with shell=True
def run_command(cmd):
    subprocess.run(cmd, shell=True)
    subprocess.Popen("ls -la", shell=True)

# MEDIUM: File write without proper error handling
def write_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)

# LOW: Missing type hints
def calculate(x, y):
    return x + y

# Good example with proper practices
def safe_function(data: str) -> str:
    """Process data safely with type hints."""
    try:
        result = data.strip().lower()
        return result
    except Exception as e:
        print(f"Error: {e}")
        return ""

if __name__ == "__main__":
    print("Example file for testing repo-janitor")
