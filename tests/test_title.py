import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import urlsplit

from dns.exception import Timeout
from dns import rdatatype
import geoip2.errors
import pytest

from config_utils import parse_config_params, vmess_parameters
import title


TEST_UUID = "11111111-1111-4111-8111-111111111111"


@pytest.mark.parametrize(
    "value,valid,ipv6",
    [
        ("192.0.2.1", True, False),
        ("2001:db8::1", True, True),
        ("[2001:db8::1]", True, True),
        ("not-an-ip", False, False),
        (None, False, False),
        (123, False, False),
    ],
)
def test_ip_validation(value, valid, ipv6):
    assert title.is_valid_ip_address(value) is valid
    assert title.is_ipv6(value) is ipv6


@pytest.mark.parametrize("port", [0, 65536, -1, "invalid", None, True, 443.5])
def test_invalid_ports_are_rejected(port):
    with pytest.raises(ValueError):
        title.validate_config_port(port)


@pytest.mark.parametrize("port", [1, "443", 65535])
def test_valid_ports_are_accepted(port):
    assert title.validate_config_port(port) == int(port)


def test_domain_validation_uses_offline_suffix_snapshot():
    assert title.is_valid_domain("example.org")
    assert not title.is_valid_domain("localhost")
    assert not title.is_valid_domain("192.0.2.1")
    assert not title.is_valid_domain(None)


@pytest.mark.parametrize("successful_type", [rdatatype.A, rdatatype.AAAA])
def test_dns_failure_in_one_family_keeps_the_other(monkeypatch, successful_type):
    dns_resolver = MagicMock()

    def resolve(node, record_type, **kwargs):
        if record_type == successful_type:
            return [SimpleNamespace(address="192.0.2.1" if record_type == rdatatype.A else "2001:db8::1")]
        raise Timeout()

    dns_resolver.resolve.side_effect = resolve
    monkeypatch.setattr(title.resolver, "Resolver", MagicMock(return_value=dns_resolver))
    expected = "192.0.2.1" if successful_type == rdatatype.A else "2001:db8::1"
    assert title.get_ips("example.org") == {expected}
    assert dns_resolver.timeout == 2
    assert dns_resolver.lifetime == 5
    assert dns_resolver.resolve.call_count == 2


def test_no_dns_answers_returns_none(monkeypatch):
    dns_resolver = MagicMock()
    dns_resolver.resolve.return_value = []
    monkeypatch.setattr(title.resolver, "Resolver", MagicMock(return_value=dns_resolver))
    assert title.get_ips("example.org") is None


def test_literal_ipv6_needs_no_dns():
    assert title.get_ips("[2001:db8::1]") == {"2001:db8::1"}


def test_country_lookup_handles_unresolvable_host(monkeypatch):
    monkeypatch.setattr(title, "get_ips", lambda node: None)
    reader = MagicMock()
    monkeypatch.setattr(title.geoip2.database, "Reader", reader)
    assert title.get_country_from_ip("missing.example.org") == "NA"
    reader.assert_not_called()


@pytest.mark.parametrize("country_code", ["FI", None])
def test_country_lookup_normalizes_ipv6_brackets(monkeypatch, country_code):
    reader = MagicMock()
    reader.__enter__.return_value = reader
    reader.country.return_value = SimpleNamespace(country=SimpleNamespace(iso_code=country_code))
    monkeypatch.setattr(title.geoip2.database, "Reader", MagicMock(return_value=reader))
    assert title.get_country_from_ip("[2001:db8::1]") == (country_code or "NA")
    reader.country.assert_called_once_with("2001:db8::1")


def test_country_not_in_database_is_best_effort(monkeypatch):
    reader = MagicMock()
    reader.__enter__.return_value = reader
    reader.country.side_effect = geoip2.errors.AddressNotFoundError("no country")
    monkeypatch.setattr(title.geoip2.database, "Reader", MagicMock(return_value=reader))
    assert title.get_country_from_ip("192.0.2.1") == "NA"


def test_missing_geoip_database_is_best_effort():
    assert title.get_country_from_ip("192.0.2.1") == "NA"


def test_tcp_probe_closes_socket_and_uses_timeout(monkeypatch):
    connection = MagicMock()
    create = MagicMock(return_value=connection)
    monkeypatch.setattr(title.socket, "create_connection", create)
    assert title.check_port("2001:db8::1", "443", timeout=2)
    create.assert_called_once_with(("2001:db8::1", 443), timeout=2)
    connection.__exit__.assert_called_once()


def test_tcp_probe_failure_returns_false(monkeypatch):
    create = MagicMock(side_effect=OSError("refused"))
    monkeypatch.setattr(title.socket, "create_connection", create)
    assert not title.check_port("192.0.2.1", 443)


def test_invalid_port_does_not_open_socket(monkeypatch):
    create = MagicMock()
    monkeypatch.setattr(title.socket, "create_connection", create)
    assert not title.check_port("192.0.2.1", 65536)
    create.assert_not_called()


def test_ping_supports_ipv6_and_closes_socket(monkeypatch):
    connection = MagicMock()
    create = MagicMock(return_value=connection)
    monkeypatch.setattr(title.socket, "create_connection", create)
    monkeypatch.setattr(title.time, "perf_counter", MagicMock(side_effect=[1.0, 1.02]))
    assert title.ping_ip_address("2001:db8::1", 443) == 20.0
    create.assert_called_once_with(("2001:db8::1", 443), timeout=1)
    connection.__exit__.assert_called_once()


def test_reality_is_in_tls_and_network_feeds(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "NA")
    config = f"vless://{TEST_UUID}@192.0.2.1:443?security=reality&sni=example.org&type=grpc&pbk=test%3D%3D"
    modified, tls, non_tls, tcp, ws, http, grpc = title.check_modify_config([config], "REALITY", False)
    assert len(modified) == 1
    assert tls == modified == grpc
    assert non_tls == tcp == ws == http == []
    assert "VL-GRPC-RLT" in modified[0]
    assert parse_config_params(urlsplit(modified[0]).query)["pbk"] == "test=="


@pytest.mark.parametrize("protocol", ["VLESS", "TROJAN"])
def test_unknown_query_parameters_are_not_lost(protocol, monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    identifier = TEST_UUID if protocol == "VLESS" else "password"
    config = f"{protocol.lower()}://{identifier}@192.0.2.1:443?security=tls&sni=example.org&path=%2Fws%3Ftoken%3Da%3Db&ech=custom%3Dvalue"
    modified = title.check_modify_config([config], protocol, False)[0]
    parameters = parse_config_params(urlsplit(modified[0]).query)
    assert parameters["path"] == "/ws?token=a=b"
    assert parameters["ech"] == "custom=value"


@pytest.mark.parametrize("protocol", ["VLESS", "TROJAN", "VMESS"])
def test_inferred_sni_does_not_disable_certificate_verification(protocol, monkeypatch, output_directories, vmess):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    monkeypatch.setattr(title, "get_ips", lambda host: {"192.0.2.1"})
    if protocol == "VMESS":
        config = vmess(add="example.org", tls="tls")
    else:
        identifier = TEST_UUID if protocol == "VLESS" else "password"
        config = f"{protocol.lower()}://{identifier}@example.org:443?security=tls&type=tcp"
    modified = title.check_modify_config([config], protocol, False)[0][0]
    parameters = vmess_parameters(modified) if protocol == "VMESS" else parse_config_params(urlsplit(modified).query)
    assert parameters["sni"] == "example.org"
    assert "allowInsecure" not in parameters and "allowinsecure" not in parameters


def test_explicit_certificate_setting_is_preserved(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    config = f"vless://{TEST_UUID}@192.0.2.1:443?security=tls&sni=example.org&allowInsecure=1"
    modified = title.check_modify_config([config], "VLESS", False)[0][0]
    assert parse_config_params(urlsplit(modified).query)["allowInsecure"] == "1"


def test_trojan_defaults_to_tls_classification(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    modified, tls, non_tls, *_ = title.check_modify_config(["trojan://secret@192.0.2.1:443"], "TROJAN", False)
    assert len(modified) == 1
    assert tls == modified
    assert non_tls == []


def test_explicit_none_is_in_non_tls_feed(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    config = f"vless://{TEST_UUID}@192.0.2.1:443?security=none&type=ws"
    modified, tls, non_tls, tcp, ws, *_ = title.check_modify_config([config], "VLESS", False)
    assert modified == non_tls == ws
    assert tls == tcp == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"port": "invalid"},
        {"port": 65536},
        {"port": None},
        {"add": []},
        {"net": 42},
    ],
)
def test_malformed_vmess_does_not_abort_following_configs(overrides, monkeypatch, output_directories, vmess):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    modified = title.check_modify_config([vmess(**overrides), vmess()], "VMESS", False)[0]
    assert len(modified) == 1
    assert vmess_parameters(modified[0])["add"] == "192.0.2.1"


def test_invalid_vless_ports_are_skipped_without_connection_checks(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    config = f"vless://{TEST_UUID}@192.0.2.1:65536?security=none"
    assert title.check_modify_config([config], "VLESS", False)[0] == []


def test_legacy_shadowsocks_can_be_decoded(monkeypatch, output_directories):
    monkeypatch.setattr(title, "get_country_from_ip", lambda ip: "FI")
    encoded = base64.urlsafe_b64encode(b"aes-128-gcm:secret@192.0.2.1:443").decode().rstrip("=")
    modified = title.check_modify_config([f"ss://{encoded}#title"], "SHADOWSOCKS", False)[0]
    assert len(modified) == 1
    assert "@192.0.2.1:443" in modified[0]


def test_country_table_ignores_non_country_entries_and_pads_odd_rows(output_directories):
    Path("countries/fi").mkdir()
    Path("countries/invalid").mkdir()
    Path("countries/readme.md").write_text("docs")
    table = title.create_country_table("countries", "owner/fork", "branch")
    assert "Finland" in table
    assert "invalid" not in table
    assert "owner/fork/branch/countries/fi/mixed" in table
    assert len(table.splitlines()[-1].split("|")) == 8


@pytest.mark.parametrize("address", ["[192.0.2.1", "192.0.2.1]", "[2001:db8::1", "2001:db8::1]", "[[2001:db8::1]]"])
def test_unmatched_or_nested_ip_brackets_are_invalid(address):
    assert not title.is_valid_ip_address(address)
    assert not title.is_ipv6(address)


def test_missing_dns_configuration_is_best_effort(monkeypatch):
    resolver = MagicMock(side_effect=title.resolver.NoResolverConfiguration())
    monkeypatch.setattr(title.resolver, "Resolver", resolver)
    assert title.get_ips("example.org") is None
