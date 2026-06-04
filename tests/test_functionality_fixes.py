from pathlib import Path

import src.core.setcore as setcore


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


def test_harvester_writes_binary_static_files_without_encoding():
    source = Path("src/webattack/harvester/harvester.py").read_text()

    assert 'open(requested_file, "rb")' in source
    assert "line = line.encode('utf-8')" not in source
