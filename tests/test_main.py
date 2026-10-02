from datetime import datetime
import importlib
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import urlsplit
import uuid

from bs4 import BeautifulSoup
import pytest
import requests

from config_utils import vmess_parameters
import main


VLESS = "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=none&type=tcp"


def message(html):
    return BeautifulSoup(f'<div class="tgme_widget_message">{html}</div>', "html.parser").div


def test_import_does_not_collect_or_write_files(tmp_path):
    importlib.reload(main)
    assert list(tmp_path.iterdir()) == []


def test_vless_at_end_of_input_is_found():
    matches = main.find_matches(VLESS)
    assert matches[5] == [VLESS + "#VLESS"]
    assert matches[6] == []


def test_reality_and_vless_are_disjoint_even_with_html_entities():
    reality = VLESS.replace("security=none", "security=reality").replace("&type", "&amp;type")
    matches = main.find_matches(VLESS + "\n" + reality)
    assert matches[5] == [VLESS + "#VLESS"]
    assert matches[6] == [reality.replace("&amp;", "&") + "#REALITY"]


def test_malformed_vless_address_does_not_break_extraction():
    broken = "vless://id@[bad:443?security=reality"
    assert main.find_matches(broken)[6] == [broken + "#REALITY"]


@pytest.mark.parametrize(
    "scheme,index,title",
    [
        ("ss", 2, "SHADOWSOCKS"),
        ("trojan", 3, "TROJAN"),
        ("vless", 5, "VLESS"),
        ("tuic", 7, "TUIC"),
        ("hysteria", 8, "HYSTERIA"),
        ("hy2", 8, "HYSTERIA"),
        ("hysteria2", 8, "HYSTERIA"),
        ("juicity", 9, "JUICITY"),
    ],
)
def test_protocol_schemes_are_case_insensitive(scheme, index, title):
    config = f"{scheme.upper()}://id@192.0.2.1:443?type=tcp#Old"
    expected_scheme = "hy2" if scheme == "hysteria2" else scheme
    assert main.find_matches(config)[index] == [f"{expected_scheme}://id@192.0.2.1:443?type=tcp#{title}"]


def test_truncated_and_embedded_protocol_names_are_not_collected():
    assert main.find_matches(VLESS + "…")[5] == []
    assert main.find_matches("invalid-" + VLESS)[5] == []


def test_message_text_preserves_inline_code_and_line_boundaries():
    msg = message(
        '<div class="tgme_widget_message_text">'
        "<code>vless://id@<span>example.org</span>:443?type=tcp</code><br>"
        "<code>trojan://secret@192.0.2.1:443</code>"
        '<a href="https://t.me/public_channel">Join us</a></div>'
    )
    text = main.tg_message_text(msg, "config")
    assert main.find_matches(text)[5] == ["vless://id@example.org:443?type=tcp#VLESS"]
    assert main.find_matches(text)[3] == ["trojan://secret@192.0.2.1:443#TROJAN"]
    assert "https://t.me/public_channel" not in text
    assert "https://t.me/public_channel" in main.tg_message_text(msg, "url")


def test_missing_message_text_is_empty():
    assert main.tg_message_text(message("<p>photo</p>"), "config") == ""


def test_invalid_text_extractor_is_rejected():
    with pytest.raises(ValueError):
        main.tg_message_text(message('<div class="tgme_widget_message_text">text</div>'), "unknown")


def test_message_timestamp_is_timezone_aware():
    msg = message('<div class="tgme_widget_message_info"><time datetime="2026-01-01T00:00:00Z"></time></div>')
    timestamp, now, delta = main.tg_message_time(msg)
    assert timestamp.hour == 3 and timestamp.minute == 30
    assert timestamp.tzinfo == main.IRAN_TIMEZONE
    assert delta == now - timestamp


@pytest.mark.parametrize(
    "html",
    [
        "<p>no metadata</p>",
        '<div class="tgme_widget_message_info"></div>',
        '<div class="tgme_widget_message_info"><time></time></div>',
        '<div class="tgme_widget_message_info"><time datetime="2026-01-01T00:00:00"></time></div>',
    ],
)
def test_missing_or_naive_message_timestamps_are_rejected(html):
    with pytest.raises(ValueError):
        main.tg_message_time(message(html))


@pytest.mark.parametrize(
    "url,username",
    [
        ("https://t.me/public_channel/123", "public_channel"),
        ("https://t.me/s/public_channel", "public_channel"),
        ("HTTPS://TELEGRAM.ME/Public_Channel", "Public_Channel"),
        ("www.t.me/public_channel", "public_channel"),
        ("tg.dev/public_channel", "public_channel"),
    ],
)
def test_telegram_username_extraction(url, username):
    assert main.tg_username_extract(url) == username


@pytest.mark.parametrize(
    "url",
    [
        "https://t.me.evil.example/user",
        "https://telegramXorg/user",
        "https://example.org/user",
        "https://t.me",
        "https://t.me/s",
        "javascript://t.me/user",
    ],
)
def test_non_telegram_urls_are_rejected(url):
    with pytest.raises(ValueError):
        main.tg_username_extract(url)


def test_telegram_http_failures_are_not_empty_channel_results(monkeypatch):
    def fail(url):
        raise requests.HTTPError("429 Too Many Requests")

    monkeypatch.setattr(main, "fetch_text", fail)
    with pytest.raises(requests.HTTPError):
        main.tg_channel_messages("public_channel")


def test_telegram_html_is_parsed(monkeypatch):
    monkeypatch.setattr(main, "fetch_text", lambda url: '<div class="tgme_widget_message">hello</div>')
    assert len(main.tg_channel_messages("public_channel")) == 1


@pytest.mark.parametrize(
    "path,origin",
    [
        ("soroushmirzaei/telegram-configs-collector/main/channels/protocols/vless", "channels"),
        ("0xjavid/telegram-configs-collector/main/channels/protocols/vless", "channels"),
        ("0xjavid/telegram-configs-collector/main/protocols/vless", "internal"),
        ("soroushmirzaei/some-other-project/main/channels/data", "external"),
        ("other/project/main/channels/data", "external"),
    ],
)
def test_subscription_origin_uses_repository_not_author_substrings(path, origin):
    assert main.subscription_origin("https://raw.githubusercontent.com/" + path) == origin


def test_custom_fork_channel_feeds_are_recognized(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/fork")
    assert (
        main.subscription_origin("https://raw.githubusercontent.com/owner/fork/main/channels/protocols/vless")
        == "channels"
    )


def test_title_placeholders_use_valid_uuids():
    reality, vless, vmess, trojan, shadowsocks = main.create_title("Title 🌍", 1080)
    assert uuid.UUID(urlsplit(vless).username)
    assert vmess_parameters(vmess)["ps"] == "Title 🌍"
    assert all("127.0.0.1" in config for config in (reality, vless, trojan, shadowsocks))


@pytest.mark.parametrize(
    "day,hour,expected",
    [
        (1, 0, True),
        (15, 0, True),
        (1, 1, False),
        (15, 23, False),
        (2, 0, False),
        (30, 0, False),
    ],
)
def test_reset_schedule(day, hour, expected):
    assert main.should_reset_outputs(SimpleNamespace(day=day, hour=hour)) is expected


def test_reset_includes_layers_and_subscribe_but_preserves_docs(output_directories):
    for name in ("layers/ipv4", "subscribe/layers/ipv4", "countries/fi/mixed", "channels/networks/tcp"):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old configs")
    Path("layers/readme.md").write_text("documentation")
    Path("splitted/no-match").write_text("diagnostic")
    main.reset_collected_configs()
    assert Path("layers/ipv4").read_text() == ""
    assert Path("subscribe/layers/ipv4").read_text() == ""
    assert Path("countries/fi/mixed").read_text() == ""
    assert Path("layers/readme.md").read_text() == "documentation"
    assert Path("splitted/no-match").read_text() == "diagnostic"


@pytest.mark.parametrize("timestamp", ["2025-07-03 00:01:23.526628+03:30\n", "2026-01-01 00:00:00+03:30"])
def test_update_timestamp_accepts_optional_microseconds_and_newline(timestamp):
    Path("last update").write_text(timestamp)
    assert main.read_last_update().tzinfo == main.IRAN_TIMEZONE


def test_naive_update_timestamp_is_rejected():
    Path("last update").write_text("2026-01-01 00:00:00")
    with pytest.raises(ValueError, match="timezone"):
        main.read_last_update()


def test_failed_collection_does_not_advance_checkpoint(monkeypatch):
    original = "2025-07-03 00:01:23.526628+03:30"
    Path("last update").write_text(original)
    Path("feed").write_text("existing configs")

    def fail(previous, current):
        assert Path("last update").read_text() == original
        raise RuntimeError("source failure")

    monkeypatch.setattr(main, "collect_configs", fail)
    with pytest.raises(RuntimeError, match="source failure"):
        main.main()
    assert Path("last update").read_text() == original
    assert Path("feed").read_text() == "existing configs"


def test_successful_collection_advances_checkpoint_only_at_end(monkeypatch):
    original = "2025-07-03 00:01:23.526628+03:30"
    Path("last update").write_text(original)
    captured = []

    def collect(previous, current):
        assert previous == datetime.fromisoformat(original)
        assert Path("last update").read_text() == original
        captured.append(current)

    monkeypatch.setattr(main, "collect_configs", collect)
    main.main()
    assert main.read_last_update() == captured[0]


def test_readme_rendering_is_fork_aware_and_keeps_documentation(monkeypatch, output_directories):
    Path("countries/fi").mkdir()
    Path("countries/readme.md").write_text("not a country")
    Path("countries/invalid-directory").mkdir()
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/fork")
    monkeypatch.setenv("SUBSCRIPTION_BRANCH", "release")
    rendered = main.render_readme()
    assert "https://raw.githubusercontent.com/owner/fork/release/countries/fi/mixed" in rendered
    assert "## Development" in rendered
    assert "## Running the Collector" in rendered
    assert "{{" not in rendered
    assert "invalid-directory" not in rendered
    main.write_readme()
    assert Path("readme.md").read_text() == rendered


def test_default_readme_links_point_to_this_fork(monkeypatch, output_directories):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("SUBSCRIPTION_BRANCH", raising=False)
    rendered = main.render_readme()
    assert "raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/vless" in rendered


def test_html_subscription_content_uses_bounded_fetch(monkeypatch):
    fetch = MagicMock(return_value="<pre>trojan://secret@192.0.2.1:443</pre>")
    monkeypatch.setattr(main, "fetch_text", fetch)
    assert main.html_content("https://example.org/feed") == "trojan://secret@192.0.2.1:443"
    fetch.assert_called_once_with("https://example.org/feed")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("https://example.org/sub?token=abc%3D%3D", ["https://example.org/sub?token=abc%3D%3D"]),
        ("HTTP://example.org/sub.txt", ["HTTP://example.org/sub.txt"]),
        ("t.me/public_channel", ["t.me/public_channel"]),
        ("www.example.org/sub", ["www.example.org/sub"]),
        ('<a href="https://example.org/sub">Subscribe</a>', ["https://example.org/sub"]),
        ("(https://example.org/sub)", ["https://example.org/sub"]),
        ("https://one.example/sub\nhttps://two.example/sub", ["https://one.example/sub", "https://two.example/sub"]),
        ("user@sub.example.org", []),
    ],
)
def test_url_discovery_preserves_supported_formats(text, expected):
    assert main.find_matches(text)[1] == expected


def test_url_discovery_handles_backtracking_attack_with_a_deadline(tmp_path):
    # A subprocess deadline prevents the vulnerable legacy matcher from hanging
    # the entire test suite if it is accidentally reintroduced.
    script = """
import socket
import requests
from dns import resolver

def forbidden(*args, **kwargs):
    raise AssertionError("Regression tests must not use the network")

requests.sessions.Session.request = forbidden
resolver.Resolver.resolve = forbidden
socket.create_connection = forbidden
socket.gethostbyname = forbidden
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden

from main import find_matches
url = "https://example.org/" + "!" * 256
assert find_matches(url)[1] == [url]
assert find_matches("a." * 4096 + "!")[1] == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(main.__file__).parent), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
