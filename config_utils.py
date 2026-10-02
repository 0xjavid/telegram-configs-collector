"""Offline parsing and identity helpers shared by the collector and its tests."""

import base64
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SUPPORTED_SCHEMES = frozenset({"ss", "trojan", "vmess", "vless", "tuic", "hysteria", "hy2", "hysteria2", "juicity"})
PARAMETER_NAMES = {
    name.lower(): name
    for name in (
        "security",
        "flow",
        "sni",
        "encryption",
        "type",
        "serviceName",
        "host",
        "path",
        "headerType",
        "fp",
        "pbk",
        "sid",
        "alpn",
        "allowInsecure",
        "maxEarlyData",
        "earlyDataHeaderName",
    )
}


def decode_base64(value):
    """Decode standard or URL-safe base64, allowing omitted padding/whitespace.

    Reject non-alphabet characters rather than silently discarding them.
    """
    compact = "".join(value.split())
    if not compact or len(compact) % 4 == 1:
        raise ValueError("Invalid base64 length")
    compact += "=" * (-len(compact) % 4)
    return base64.b64decode(compact, altchars=b"-_", validate=True)


def is_valid_base64(value):
    try:
        decode_base64(value)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def decode_subscription(content):
    """Decode encoded text feeds, leaving plain text or non-UTF-8 data intact."""
    try:
        return decode_base64(content).decode("utf-8")
    except (ValueError, TypeError, AttributeError):
        return content


def vmess_parameters(config):
    """Read VMess JSON without network requests or filesystem changes."""
    scheme, separator, payload = config.strip().partition("://")
    if not separator or scheme.lower() != "vmess":
        raise ValueError("Not a VMess configuration")
    parameters = json.loads(decode_base64(payload.split("#", 1)[0]).decode("utf-8"))
    if not isinstance(parameters, dict):
        raise ValueError("VMess parameters must be a JSON object")
    return {key.lower(): value for key, value in parameters.items()}


def encode_vmess(parameters):
    payload = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    return "vmess://" + base64.b64encode(payload.encode("utf-8")).decode("ascii")


def parse_config_params(query):
    """Normalize known parameter names while retaining values and unknown keys."""
    return {PARAMETER_NAMES.get(key.lower(), key): value for key, value in parse_qsl(query, keep_blank_values=True)}


def encode_config_params(parameters):
    return urlencode([(key, value) for key, value in parameters.items() if value not in ("", None)])


def configuration_identity(config):
    """Ignore display titles, never credentials, destinations or parameters.

    VMess identity is its JSON payload without `ps`; URI query ordering is not
    significant. Keeping credentials and parameters prevents different working
    configurations on the same server/port from being collapsed into one.
    """
    if not isinstance(config, str):
        raise ValueError("Configuration must be text")
    parts = urlsplit(config.strip().split("#", 1)[0])
    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES or not parts.netloc:
        raise ValueError("Unsupported or empty configuration")
    if scheme == "vmess":
        parameters = vmess_parameters(config)
        parameters.pop("ps", None)
        return scheme, json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True), key=lambda pair: pair[0]))
    return scheme, urlunsplit((scheme, parts.netloc, parts.path, query, ""))


def deduplicate_configs(configurations):
    """Remove actual duplicates in input order, skipping malformed entries."""
    unique = {}
    for config in configurations:
        try:
            identity = configuration_identity(config)
        except (ValueError, TypeError):
            continue
        unique.setdefault(identity, config)
    return list(unique.values())


def split_configs(configurations, count=10):
    """Split into at most `count` roughly equal chunks, including empty input."""
    if count < 1:
        raise ValueError("Chunk count must be positive")
    if not configurations:
        return []
    size = (len(configurations) + count - 1) // count
    return [configurations[index : index + size] for index in range(0, len(configurations), size)]
