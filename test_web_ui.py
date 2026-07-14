from __future__ import annotations

import base64
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess

from secure_vault import SecureVault, __version__
from tools.generate_release_artifacts import read_project_metadata


ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
WEB_BRIDGE = ROOT / "tests" / "web_interop.mjs"


class _MarkupInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def _run_web_bridge(payload: dict[str, str]) -> str:
    node = shutil.which("node")
    assert node is not None, "Node.js is required for browser interoperability tests."
    result = subprocess.run(
        [node, str(WEB_BRIDGE)],
        cwd=ROOT,
        input=json.dumps(payload),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _derive_fixture_key(vault: SecureVault, passphrase: str, salt: bytes) -> bytes:
    config = vault.CURRENT_KDF_CONFIG
    return vault._derive_key(
        passphrase,
        salt,
        config["ops"],
        config["mem"],
        config["p"],
        config["key_len"],
    )


def test_browser_handler_preserves_plaintext_whitespace_for_python_decryption() -> None:
    vault = SecureVault()
    plaintext = "  leading spaces\n\tand trailing whitespace  \n"
    passphrase = "interoperability-test-passphrase"
    salt = bytes(range(16))
    nonce = bytes(range(32, 44))
    key = _derive_fixture_key(vault, passphrase, salt)

    blob = _run_web_bridge(
        {
            "mode": "browser-encrypt",
            "plaintext": plaintext,
            "passphrase": passphrase,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "key_b64": base64.b64encode(key).decode("ascii"),
        }
    )

    assert vault.decrypt(blob, passphrase) == plaintext


def test_python_payload_decrypts_with_browser_crypto_path() -> None:
    vault = SecureVault()
    plaintext = "Python to browser: café, emoji 🔐, and newlines\nremain intact."
    passphrase = "python-to-browser-passphrase"
    blob = vault.encrypt(plaintext, passphrase)
    packet = json.loads(blob)
    salt = base64.b64decode(packet["header"]["salt"], validate=True)
    key = _derive_fixture_key(vault, passphrase, salt)

    browser_plaintext = _run_web_bridge(
        {
            "mode": "browser-decrypt",
            "blob": blob,
            "passphrase": passphrase,
            "key_b64": base64.b64encode(key).decode("ascii"),
        }
    )

    assert browser_plaintext == plaintext


def test_runtime_version_is_the_package_metadata_source() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'dynamic = ["version"]' in pyproject
    assert '[tool.hatch.version]\npath = "secure_vault.py"' in pyproject
    assert read_project_metadata()["version"] == __version__


def test_form_controls_have_programmatic_labels_and_button_types() -> None:
    parser = _MarkupInventory()
    parser.feed(INDEX.read_text(encoding="utf-8"))
    ids = {attrs["id"] for _, attrs in parser.elements if attrs.get("id")}
    labels = [attrs for tag, attrs in parser.elements if tag == "label"]
    buttons = [attrs for tag, attrs in parser.elements if tag == "button"]

    assert labels
    assert all(label.get("for") in ids for label in labels)
    assert buttons
    assert all(button.get("type") == "button" for button in buttons)


def test_tabs_statuses_focus_and_motion_have_accessible_contracts() -> None:
    parser = _MarkupInventory()
    html = INDEX.read_text(encoding="utf-8")
    parser.feed(html)
    by_id = {
        attrs["id"]: attrs
        for _, attrs in parser.elements
        if attrs.get("id")
    }

    assert by_id["tab-encrypt"]["role"] == "tab"
    assert by_id["tab-decrypt"]["role"] == "tab"
    assert by_id["panel-encrypt"]["role"] == "tabpanel"
    assert by_id["panel-decrypt"]["role"] == "tabpanel"
    assert by_id["enc-status"]["aria-live"] == "polite"
    assert by_id["dec-status"]["aria-live"] == "polite"
    assert ":focus-visible" in html
    assert "prefers-reduced-motion: reduce" in html
    assert "event.key === 'ArrowRight'" in html
