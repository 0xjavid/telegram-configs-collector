"""Exercise the whole collection pipeline using synthetic, offline sources."""

from datetime import datetime
import json
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
import pytest
import requests

from config_utils import decode_subscription, vmess_parameters
import main
import title


TEST_UUID = "11111111-1111-4111-8111-111111111111"
OLD_CHECKPOINT = "2026-01-01 00:00:00.000000+03:30"
NOW = datetime.fromisoformat("2026-10-02T12:00:00+03:30")


def seed_sources(channels, subscriptions):
    Path("telegram channels.json").write_text(json.dumps(channels))
    Path("invalid telegram channels.json").write_text("[]")
    Path("subscription links.json").write_text(json.dumps(subscriptions))
    Path("last update").write_text(OLD_CHECKPOINT)


def telegram_message(config):
    soup = BeautifulSoup(
        '<div class="tgme_widget_message">'
        '<div class="tgme_widget_message_info"><time datetime="2026-10-01T12:00:00Z"></time></div>'
        f'<div class="tgme_widget_message_text"><code>{config.replace("&", "&amp;")}</code></div></div>',
        "html.parser",
    )
    return soup.div


def destinations(path):
    result = set()
    for config in decode_subscription(Path(path).read_text()).splitlines():
        if not config:
            continue
        if config.startswith("vmess://"):
            address = vmess_parameters(config)["add"]
        else:
            address = urlsplit(config).hostname
        if address != "127.0.0.1":
            result.add(address)
    return result


@pytest.fixture
def collection_environment(monkeypatch):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz)

    monkeypatch.setattr(main, "datetime", FixedDateTime)
    monkeypatch.setattr(main, "refresh_geoip_database", lambda: True)
    monkeypatch.setattr(main, "fetch_text", lambda url: "[]")
    monkeypatch.setattr(main, "should_reset_outputs", lambda timestamp: False)
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    monkeypatch.setattr(title, "check_port", lambda ip, port: True)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("SUBSCRIPTION_BRANCH", raising=False)


def test_collection_keeps_channels_separate_and_vmess_servers_distinct(collection_environment, monkeypatch, vmess):
    external = "https://example.org/subscription"
    channel_feed = "https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/vless"
    seed_sources(["public_channel", "temporarily_unavailable"], [external, channel_feed])
    channel_config = f"vless://{TEST_UUID}@192.0.2.1:443?security=none&type=ws"
    cached_channel = f"vless://{TEST_UUID}@192.0.2.3:443?security=none&type=grpc"
    subscription_configs = [
        "trojan://secret@198.51.100.2:443?security=tls&sni=example.org",
        vmess(add="203.0.113.4"),
        vmess(add="203.0.113.5"),
    ]

    def channels(username):
        if username == "temporarily_unavailable":
            raise requests.Timeout("temporary failure")
        return [telegram_message(channel_config)] if username == "public_channel" else []

    contents = {external: "\n".join(subscription_configs), channel_feed: cached_channel}
    monkeypatch.setattr(main, "tg_channel_messages", channels)
    monkeypatch.setattr(main, "html_content", lambda url: contents[url])
    main.main()

    all_addresses = {"192.0.2.1", "192.0.2.3", "198.51.100.2", "203.0.113.4", "203.0.113.5"}
    assert destinations("splitted/mixed") == all_addresses
    assert destinations("splitted/channels") == {"192.0.2.1", "192.0.2.3"}
    assert destinations("channels/protocols/vless") == {"192.0.2.1", "192.0.2.3"}
    assert destinations("subscribe/protocols/vmess") == {"203.0.113.4", "203.0.113.5"}
    assert destinations("countries/fi/mixed") == all_addresses
    assert destinations("layers/ipv4") == all_addresses
    assert "temporarily_unavailable" in json.loads(Path("telegram channels.json").read_text())
    assert main.read_last_update() == NOW
    assert "## Development" in Path("readme.md").read_text()


def test_complete_source_failure_preserves_feeds_and_checkpoint(collection_environment, monkeypatch):
    seed_sources(["public_channel"], ["https://example.org/feed"])
    main.prepare_output_directories()
    feed_paths = ["layers/ipv4", "subscribe/layers/ipv4", "splitted/mixed", "countries/fi/mixed"]
    for name in feed_paths:
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("existing configs")

    def fail(*args):
        raise requests.HTTPError("503 Service Unavailable")

    monkeypatch.setattr(main, "should_reset_outputs", lambda timestamp: True)
    monkeypatch.setattr(main, "tg_channel_messages", fail)
    monkeypatch.setattr(main, "html_content", fail)
    monkeypatch.setattr(main, "fetch_text", fail)
    with pytest.raises(RuntimeError, match="No configurations collected"):
        main.main()
    assert Path("last update").read_text() == OLD_CHECKPOINT
    assert json.loads(Path("telegram channels.json").read_text()) == ["public_channel"]
    assert all(Path(name).read_text() == "existing configs" for name in feed_paths)


def test_all_malformed_configs_cannot_clear_outputs_on_reset_day(collection_environment, monkeypatch, vmess):
    seed_sources([], ["https://example.org/feed"])
    main.prepare_output_directories()
    Path("splitted/mixed").write_text("existing configs")
    monkeypatch.setattr(main, "should_reset_outputs", lambda timestamp: True)
    monkeypatch.setattr(main, "html_content", lambda url: vmess(port="invalid"))
    with pytest.raises(RuntimeError, match="No usable configurations"):
        main.main()
    assert Path("splitted/mixed").read_text() == "existing configs"
    assert Path("last update").read_text() == OLD_CHECKPOINT


@pytest.mark.parametrize(
    "protocol,config",
    [
        ("hysteria", "hy2://secret@192.0.2.9:443?sni=example.org"),
        ("tuic", f"tuic://{TEST_UUID}:secret@192.0.2.9:443?sni=example.org"),
        ("juicity", f"juicity://{TEST_UUID}:secret@192.0.2.9:443?sni=example.org"),
    ],
)
def test_udp_only_input_does_not_crash_empty_mixed_chunking(collection_environment, monkeypatch, protocol, config):
    seed_sources([], ["https://example.org/feed"])
    monkeypatch.setattr(main, "html_content", lambda url: config)
    main.main()
    assert destinations(f"protocols/{protocol}") == {"192.0.2.9"}
    assert all(Path(f"splitted/mixed-{index}").read_text() == "" for index in range(10))
    assert main.read_last_update() == NOW
