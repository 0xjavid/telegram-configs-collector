import base64
import json

import pytest

from config_utils import (
    configuration_identity,
    decode_base64,
    decode_subscription,
    deduplicate_configs,
    encode_config_params,
    is_valid_base64,
    parse_config_params,
    split_configs,
    vmess_parameters,
)
import main


@pytest.mark.parametrize("encoder", [base64.b64encode, base64.urlsafe_b64encode])
@pytest.mark.parametrize("padded", [True, False])
def test_subscription_decodes_base64_with_whitespace_and_optional_padding(encoder, padded):
    text = "trojan://secret@192.0.2.1:443#تست 🌍"
    encoded = encoder(text.encode()).decode()
    if not padded:
        encoded = encoded.rstrip("=")
    wrapped = "\r\n" + encoded[:12] + "\n" + encoded[12:] + "\r\n"
    assert decode_subscription(wrapped) == text
    assert main.decode_string(wrapped) == text


@pytest.mark.parametrize("value", ["", "a", "hello!", "abc$def=", None, 123])
def test_invalid_base64_is_rejected(value):
    assert not is_valid_base64(value)
    with pytest.raises((ValueError, TypeError, AttributeError)):
        decode_base64(value)


@pytest.mark.parametrize("text", ["trojan://a@192.0.2.1:443\n", "//8=", "not encoded!"])
def test_plain_text_and_binary_feeds_are_not_corrupted(text):
    assert decode_subscription(text) == text


def test_query_parameters_keep_padding_and_unknown_fields():
    query = "Security=tls&SERVICEname=test&pbk=abc%3D%3D&path=%2Fws%3Ftoken%3Da%3Db&ech=new%2Bvalue"
    parsed = parse_config_params(query)
    assert parsed == {
        "security": "tls",
        "serviceName": "test",
        "pbk": "abc==",
        "path": "/ws?token=a=b",
        "ech": "new+value",
    }
    assert parse_config_params(encode_config_params(parsed)) == parsed


def test_vmess_identity_ignores_title_and_json_key_order(vmess):
    first = vmess(ps="First")
    parameters = dict(reversed(list(vmess_parameters(first).items())))
    parameters["ps"] = "Second"
    second = "vmess://" + base64.b64encode(json.dumps(parameters).encode()).decode().rstrip("=")
    assert configuration_identity(first) == configuration_identity(second)
    assert main.remove_duplicate_modified([first, second, first]) == [first]
    arrays = main.remove_duplicate([], [], [first, second], [], [], [], [], [])
    assert len(arrays[2]) == 1
    assert vmess_parameters(arrays[2][0])["ps"] == "VMESS"


def test_vmess_servers_and_credentials_on_the_same_port_are_distinct(vmess):
    configs = [
        vmess(add="192.0.2.1"),
        vmess(add="192.0.2.2"),
        vmess(id="22222222-2222-4222-8222-222222222222"),
        vmess(path="/different"),
    ]
    assert main.remove_duplicate_modified(configs) == configs


@pytest.mark.parametrize("scheme", ["ss", "trojan", "vless", "tuic", "hy2", "juicity"])
def test_uri_credentials_and_parameters_are_not_collapsed(scheme):
    first = f"{scheme}://first@192.0.2.1:443?type=ws&security=none#First"
    duplicate = f"{scheme}://first@192.0.2.1:443?security=none&type=ws#Second"
    other_credentials = first.replace("first@", "second@")
    other_parameters = first.replace("type=ws", "type=grpc")
    configs = [first, duplicate, other_credentials, other_parameters]
    assert deduplicate_configs(configs) == [first, other_credentials, other_parameters]


def test_vmess_case_sensitive_values_are_retained(vmess):
    configs = [vmess(path="/CaseSensitive"), vmess(path="/casesensitive")]
    assert deduplicate_configs(configs) == configs


def test_hysteria_parameter_identity():
    configs = [
        "hysteria://192.0.2.1:443?auth=first#title",
        "hysteria://192.0.2.1:443?auth=second#title",
    ]
    assert deduplicate_configs(configs + configs) == configs


def test_legacy_encoded_shadowsocks_is_retained():
    payload = base64.b64encode(b"aes-128-gcm:password@192.0.2.1:443").decode()
    config = f"ss://{payload}#Original"
    assert deduplicate_configs([config, f"ss://{payload}#New"]) == [config]


def test_malformed_entries_do_not_abort_deduplication(vmess):
    good = vmess()
    assert deduplicate_configs([None, "vmess://!!!!", "not a config", "https://example.org", good]) == [good]


@pytest.mark.parametrize("payload", [b"[]", b"null", b'"text"', b"not JSON", b"\xff"])
def test_non_object_vmess_is_rejected(payload):
    config = "vmess://" + base64.b64encode(payload).decode()
    assert main.decode_vmess(config) is None
    assert deduplicate_configs([config]) == []


def test_exact_deduplication_is_stable_and_keeps_titles_when_requested(vmess):
    one, two = vmess(ps="One"), vmess(ps="Two")
    result = main.remove_duplicate([], [], [one, two, one], [], [], [], [], [], vmess_decode_dedup=False)
    assert result[2] == [one, two]


@pytest.mark.parametrize("length", [0, 1, 5, 10, 11, 30, 101])
def test_splitting_handles_empty_and_nonempty_input(length):
    configs = list(range(length))
    chunks = split_configs(configs)
    assert len(chunks) <= 10
    assert [item for chunk in chunks for item in chunk] == configs
    assert all(chunks)


def test_chunks_are_independent_of_original_list():
    configs = [1, 2, 3]
    chunks = split_configs(configs)
    chunks[0].insert(0, "header")
    assert configs == [1, 2, 3]


def test_invalid_chunk_count_is_rejected():
    with pytest.raises(ValueError):
        split_configs([], count=0)


def test_repeated_query_values_keep_their_order_in_identity():
    first = "vless://id@192.0.2.1:443?security=none&security=tls"
    second = "vless://id@192.0.2.1:443?security=tls&security=none"
    assert deduplicate_configs([first, second]) == [first, second]
