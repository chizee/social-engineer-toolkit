import ast
import os
from pathlib import Path

import pytest

import src.core.setcore as setcore
import src.qrcode.qrgenerator as qrgenerator


def test_safe_join_webroot_allows_files_under_root(tmp_path):
    webroot = tmp_path / "web_clone"
    webroot.mkdir()

    resolved = setcore.safe_join_webroot(str(webroot), "/assets/site.css")

    assert resolved == str(webroot / "assets/site.css")


def test_safe_join_webroot_blocks_traversal(tmp_path):
    webroot = tmp_path / "web_clone"
    webroot.mkdir()

    assert setcore.safe_join_webroot(str(webroot), "/../secret.txt") is None
    assert setcore.safe_join_webroot(str(webroot), "/%2e%2e/secret.txt") is None


def test_meta_path_accepts_configured_msfconsole_executable(monkeypatch):
    def fake_check_config(key):
        if key == "METASPLOIT_PATH=":
            return "/opt/metasploit-framework/bin/msfconsole"
        if key == "METASPLOIT_MODE=":
            return "ON"
        return ""

    monkeypatch.setattr(setcore, "check_config", fake_check_config)
    monkeypatch.setattr(
        setcore.os.path,
        "isfile",
        lambda path: path == "/opt/metasploit-framework/bin/msfconsole",
    )

    assert setcore.meta_path() == "/opt/metasploit-framework/bin/"


def test_smtp_auth_b64_returns_ascii_text():
    encoded = setcore.smtp_auth_b64("user@example.com")

    assert encoded == "dXNlckBleGFtcGxlLmNvbQ=="
    assert isinstance(encoded, str)


def test_legacy_payload_binary_path_reports_missing_payload(tmp_path):
    with pytest.raises(FileNotFoundError) as excinfo:
        setcore.legacy_payload_binary_path(str(tmp_path), "shellcode/pyinject")

    assert "pyinjector.binary" in str(excinfo.value)
    assert "legacy Java shellcode injector payload is unavailable" in str(excinfo.value)


def test_harvester_writes_binary_static_files_without_encoding():
    source = Path("src/webattack/harvester/harvester.py").read_text()

    assert 'open(requested_file, "rb")' in source
    assert "line = line.encode('utf-8')" not in source


def test_legacy_payload_injectors_use_valid_choice_names():
    source = Path("src/core/payloadgen/create_payloads.py").read_text()

    assert "legacy_payload_binary_path(definepath, choice1)" in source
    assert "shellcode/multipyiject" not in source


def test_binary2teensy_no_longer_uses_removed_python2_builtins():
    tree = ast.parse(Path("src/teensy/binary2teensy.py").read_text())

    removed_builtin_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"file", "unicode"}
    }

    assert removed_builtin_calls == set()


def test_qrcode_generator_creates_reports_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(qrgenerator.core, "userconfigpath", str(tmp_path) + os.sep)

    qrgenerator.gen_qrcode("https://example.com")

    assert (tmp_path / "reports/qrcode_attack.png").is_file()


def test_set_http_server_uses_python3_header_and_aes_byte_handling():
    source = Path("src/payloads/set_payloads/set_http_server.py").read_text()

    assert ".headers.get(" in source
    assert ".headers.getheader(" not in source
    assert 'secret = b"' in source
    assert "AES.new(secret, AES.MODE_ECB)" in source
    assert "[0-9a-fA-F]" in source


def test_encrypt_aes_accepts_bytes_secret_and_text_payload():
    encrypted = setcore.encryptAES(b"1" * 32, "payload")

    assert isinstance(encrypted, str)
    assert encrypted
    assert not encrypted.startswith("b'")


def test_payload_aes_modules_use_explicit_mode_and_python3_urllib():
    paths = [
        Path("src/core/setcore.py"),
        Path("src/payloads/set_payloads/http_shell.py"),
        Path("src/payloads/set_payloads/listener.py"),
    ]

    for path in paths:
        source = path.read_text()
        assert "AES.new(secret, AES.MODE_ECB)" in source
        assert "AES.new(secret)" not in source

    http_shell = Path("src/payloads/set_payloads/http_shell.py").read_text()
    assert "from urllib import parse, request" in http_shell
    assert "urllib.request" not in http_shell
    assert "urllib.parse" not in http_shell

    listener = Path("src/payloads/set_payloads/listener.py").read_text()
    assert "import _thread as thread" in listener
    assert "conn.sendall(_socket_bytes(" in listener
    assert "conn.send(str(" not in listener


def test_remaining_python3_text_boundaries_are_normalized():
    sd2teensy = Path("src/teensy/sd2teensy.py").read_text()
    assert 'base64.b64encode(powershell_command.encode("utf-8")).decode("ascii")' in sd2teensy
    assert "core.powershell_encodedcommand(powershell_command)" in sd2teensy

    smtp_web = Path("src/phishing/smtp/client/smtp_web.py").read_text()
    assert 'str(base64.b64encode(to.encode()))' not in smtp_web
    assert "smtp_auth_b64(to)" in smtp_web

    setcore = Path("src/core/setcore.py").read_text()
    assert "# import the threading, socketserver, and simplehttpserver\n        import thread" not in setcore
    assert 'conn.sendall(command.encode("utf-8"))' in setcore
    assert "conn.send(command)" not in setcore
