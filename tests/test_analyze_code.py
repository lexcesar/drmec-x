"""Unit tests for the analyze_code tool — tests every regex pattern.

We import only analyze_code and its patterns directly to avoid
requiring langchain/chromadb for unit tests.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import the function and patterns directly without triggering langchain imports
# by reconstructing the pure-logic function here
from importlib.util import spec_from_file_location, module_from_spec

def _load_analyze_code():
    """Load only the analyze_code function and patterns from tools.py
    by reading the source and extracting the pure logic."""
    tools_path = Path(__file__).resolve().parent.parent / "tools.py"
    source = tools_path.read_text()

    # Extract VULNERABILITY_PATTERNS and analyze_code from source
    # We create a minimal module with just the patterns and function
    namespace = {"re": re}

    # Extract patterns block
    pattern_start = source.index("VULNERABILITY_PATTERNS = [")
    pattern_end = source.index("\n]\n", pattern_start) + 3
    exec(source[pattern_start:pattern_end], namespace)

    # Extract analyze_code function
    func_start = source.index("def analyze_code(")
    # Find the next def or tool separator
    next_section = source.find("\n# ----", func_start + 1)
    if next_section == -1:
        func_source = source[func_start:]
    else:
        func_source = source[func_start:next_section]

    namespace["VULNERABILITY_PATTERNS"] = namespace["VULNERABILITY_PATTERNS"]
    exec(func_source, namespace)
    return namespace["analyze_code"]

analyze_code = _load_analyze_code()


def test_hardcoded_password():
    code = 'password = "admin123"'
    result = analyze_code(code)
    assert "Hardcoded credential" in result
    assert "Line 1" in result


def test_hardcoded_api_key():
    code = "api_key = 'sk-secret-key-12345'"
    result = analyze_code(code)
    assert "Hardcoded credential" in result


def test_hardcoded_token():
    code = 'token = "eyJhbGciOiJIUzI1NiJ9"'
    result = analyze_code(code)
    assert "Hardcoded credential" in result


def test_eval_usage():
    code = "result = eval(user_input)"
    result = analyze_code(code)
    assert "dangerous function" in result
    assert "A03:2021" in result


def test_exec_usage():
    code = "exec(code_string)"
    result = analyze_code(code)
    assert "dangerous function" in result


def test_compile_usage():
    code = "compiled = compile(source, '<string>', 'exec')"
    result = analyze_code(code)
    assert "dangerous function" in result


def test_sql_injection_concatenation():
    code = 'query = "SELECT * FROM users WHERE id=" + user_id'
    result = analyze_code(code)
    assert "SQL injection" in result
    assert "A03:2021" in result


def test_sql_injection_format():
    code = 'query = "SELECT * FROM users WHERE id={}".format(user_id)'
    result = analyze_code(code)
    assert "SQL injection" in result


def test_subprocess_shell_true():
    code = 'subprocess.run(cmd, shell=True)'
    result = analyze_code(code)
    assert "shell=True" in result
    assert "command injection" in result


def test_pickle_load():
    code = "data = pickle.load(file)"
    result = analyze_code(code)
    assert "pickle" in result
    assert "deserialization" in result


def test_pickle_loads():
    code = "data = pickle.loads(raw_bytes)"
    result = analyze_code(code)
    assert "pickle" in result


def test_unsafe_yaml():
    code = "config = yaml.load(data)"
    result = analyze_code(code)
    assert "YAML" in result


def test_safe_yaml_no_alert():
    """yaml.load with Loader should NOT trigger (negative test)."""
    code = "config = yaml.load(data, Loader=yaml.SafeLoader)"
    result = analyze_code(code)
    assert "YAML" not in result


def test_os_system():
    code = "os.system(user_command)"
    result = analyze_code(code)
    assert "OS command execution" in result


def test_os_popen():
    code = "os.popen(cmd)"
    result = analyze_code(code)
    assert "OS command execution" in result


def test_ssl_verify_false():
    code = "requests.get(url, verify=False)"
    result = analyze_code(code)
    assert "SSL verification disabled" in result
    assert "A02:2021" in result


def test_md5_usage():
    code = "hash_val = md5(data)"
    result = analyze_code(code)
    assert "weak hashing" in result


def test_sha1_usage():
    code = "hash_val = sha1(data)"
    result = analyze_code(code)
    assert "weak hashing" in result


def test_insecure_random():
    code = "token = random.random()"
    result = analyze_code(code)
    assert "non-cryptographic random" in result


def test_innerhtml_xss():
    code = 'element.innerHTML = user_input'
    result = analyze_code(code)
    assert "XSS" in result


def test_document_write_xss():
    code = "document.write(data)"
    result = analyze_code(code)
    assert "XSS" in result


def test_http_url():
    code = 'url = "http://api.example.com/data"'
    result = analyze_code(code)
    assert "HTTP" in result
    assert "HTTPS" in result


def test_debug_mode():
    code = "DEBUG = True"
    result = analyze_code(code)
    assert "Debug mode" in result
    assert "A05:2021" in result


def test_wildcard_cors():
    code = "Access-Control-Allow-Origin: *"
    result = analyze_code(code)
    assert "CORS" in result


def test_clean_code_no_findings():
    code = """import os
import hashlib

def get_password():
    return os.environ.get("DB_PASSWORD")

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
"""
    result = analyze_code(code)
    assert "No common vulnerability patterns detected" in result


def test_multiline_multiple_findings():
    code = """import os
password = "secret123"
os.system(user_input)
query = "SELECT * FROM t WHERE id=" + uid
"""
    result = analyze_code(code)
    assert "Line 2" in result  # password
    assert "Line 3" in result  # os.system
    assert "Line 4" in result  # SQL injection


def test_empty_code():
    result = analyze_code("")
    assert "No common vulnerability patterns detected" in result


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
