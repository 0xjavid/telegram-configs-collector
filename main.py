"""Collect public proxy configuration feeds; importing this module does not run it."""

import base64
from datetime import datetime, timezone, timedelta
import html
import json
import logging
import os
from pathlib import Path
import re
import string
from urllib.parse import urlsplit
import uuid

from bs4 import BeautifulSoup
import jdatetime
import requests

from collector_io import atomic_write_text, fetch_text, refresh_geoip_database
from config_utils import (
    decode_subscription, deduplicate_configs, encode_vmess,
    parse_config_params, split_configs, vmess_parameters,
)
from title import check_modify_config, create_country, create_country_table, create_internet_protocol


LOGGER = logging.getLogger(__name__)
IRAN_TIMEZONE = timezone(timedelta(hours=3, minutes=30))
DEFAULT_REPOSITORY = "0xjavid/telegram-configs-collector"
OUTPUT_DIRECTORIES = (
    "security", "protocols", "networks", "layers",
    "subscribe", "splitted", "channels", "countries",
)
TELEGRAM_DOMAINS = frozenset({"t.me", "telegram.me", "telegram.org", "telesco.pe", "tg.dev", "telegram.dog"})
README_TEMPLATE = Path(__file__).resolve().parent / "docs" / "readme-template.md"


def read_last_update(path="last update"):
    timestamp = datetime.fromisoformat(Path(path).read_text(encoding="utf-8").strip())
    if timestamp.utcoffset() is None:
        raise ValueError("The last update timestamp must include a timezone")
    return timestamp


def prepare_output_directories():
    for directory in OUTPUT_DIRECTORIES:
        Path(directory).mkdir(parents=True, exist_ok=True)
    for source in ("channels", "subscribe"):
        for category in ("security", "protocols", "networks", "layers"):
            Path(source, category).mkdir(parents=True, exist_ok=True)


def should_reset_outputs(jalali_datetime):
    return jalali_datetime.day in (1, 15) and jalali_datetime.hour == 0


def reset_collected_configs():
    for directory in OUTPUT_DIRECTORIES:
        for path in Path(directory).rglob("*"):
            if path.is_file() and path.name.lower() not in ("readme.md", "no-match"):
                path.write_text("", encoding="utf-8")


def render_readme(country_path="countries", repository=None, branch=None):
    repository = repository or os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    branch = branch or os.environ.get("SUBSCRIPTION_BRANCH", "main")
    template = README_TEMPLATE.read_text(encoding="utf-8")
    return (template.replace("{{repository}}", repository)
            .replace("{{branch}}", branch)
            .replace("{{country_table}}", create_country_table(country_path, repository, branch)))


def write_readme(path="readme.md"):
    atomic_write_text(path, render_readme())



def json_load(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def tg_channel_messages(channel_user):
    # HTTP failures must not be mistaken for deleted/empty channels.
    soup = BeautifulSoup(fetch_text(f"https://t.me/s/{channel_user}"), "html.parser")
    return soup.find_all("div", class_="tgme_widget_message")


def find_matches(text_content):
    # Initialize configuration type patterns
    pattern_telegram_user = r'(?:@)(\w{4,})'
    # Domain labels are separated by dots; URL paths use a single character
    # class. Avoid ambiguous nested repetitions on untrusted message/feed text.
    pattern_url = r"""(?i)(?<![\w@./:-])(?:https?://[^\s<>"'()\[\]{}]+|(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/[^\s<>"'()\[\]{}]*)?)"""
    pattern_shadowsocks = r"(?<![\w-])(ss://[^\s<>#]+)"
    pattern_trojan = r"(?<![\w-])(trojan://[^\s<>#]+)"
    pattern_vmess = r"(?<![\w-])(vmess://[^\s<>#]+)"
    pattern_vless = r"(?<![\w-])(vless://[^\s<>#]+)"
    pattern_tuic = r"(?<![\w-])(tuic://[^\s<>#]+)"
    pattern_hysteria = r"(?<![\w-])(hysteria://[^\s<>#]+)"
    pattern_hysteria_ver2 = r"(?<![\w-])((?:hy2|hysteria2)://[^\s<>#]+)"
    pattern_juicity = r"(?<![\w-])(juicity://[^\s<>#]+)"

    # Find all matches of patterns in text
    matches_usersname = re.findall(pattern_telegram_user, text_content, re.IGNORECASE)
    matches_url = re.findall(pattern_url, text_content, re.IGNORECASE)
    matches_shadowsocks = re.findall(pattern_shadowsocks, text_content, re.IGNORECASE)
    matches_trojan = re.findall(pattern_trojan, text_content, re.IGNORECASE)
    matches_vmess = re.findall(pattern_vmess, text_content, re.IGNORECASE)
    matches_vless = re.findall(pattern_vless, text_content, re.IGNORECASE)
    matches_reality = [config for config in matches_vless
                       if parse_config_params(html.unescape(config).partition("?")[2]).get("security", "").lower() == "reality"]
    matches_vless = [config for config in matches_vless if config not in matches_reality]
    matches_tuic = re.findall(pattern_tuic, text_content, re.IGNORECASE)
    matches_hysteria = re.findall(pattern_hysteria, text_content, re.IGNORECASE)
    matches_hysteria_ver2 = re.findall(pattern_hysteria_ver2, text_content, re.IGNORECASE)
    matches_juicity = re.findall(pattern_juicity, text_content, re.IGNORECASE)

    for matches in (matches_shadowsocks, matches_trojan, matches_vmess, matches_vless,
                    matches_reality, matches_tuic, matches_hysteria, matches_hysteria_ver2, matches_juicity):
        for index, config in enumerate(matches):
            scheme, payload = config.split("://", 1)
            scheme = "hy2" if scheme.lower() == "hysteria2" else scheme.lower()
            matches[index] = f"{scheme}://{payload}"

    # Iterate over matches to subtract titles
    for index, element in enumerate(matches_vmess):
        matches_vmess[index] = re.sub(r"#[^#]+$", "", html.unescape(element))

    for index, element in enumerate(matches_shadowsocks):
        matches_shadowsocks[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#SHADOWSOCKS")

    for index, element in enumerate(matches_trojan):
        matches_trojan[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#TROJAN")

    for index, element in enumerate(matches_vless):
        matches_vless[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#VLESS")

    for index, element in enumerate(matches_reality):
        matches_reality[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#REALITY")

    for index, element in enumerate(matches_tuic):
        matches_tuic[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#TUIC")

    for index, element in enumerate(matches_hysteria):
        matches_hysteria[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#HYSTERIA")

    for index, element in enumerate(matches_hysteria_ver2):
        matches_hysteria_ver2[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#HYSTERIA")

    for index, element in enumerate(matches_juicity):
        matches_juicity[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ "#JUICITY")

    matches_shadowsocks = [x for x in matches_shadowsocks if "…" not in x]
    matches_trojan = [x for x in matches_trojan if "…" not in x]
    matches_vmess = [x for x in matches_vmess if "…" not in x]
    matches_vless = [x for x in matches_vless if "…" not in x]
    matches_reality = [x for x in matches_reality if "…" not in x]
    matches_tuic = [x for x in matches_tuic if "…" not in x]
    matches_hysteria = [x for x in matches_hysteria if "…" not in x]
    matches_hysteria_ver2 = [x for x in matches_hysteria_ver2 if "…" not in x]
    matches_juicity = [x for x in matches_juicity if "…" not in x]

    # Extend hysteria versions
    matches_hysteria.extend(matches_hysteria_ver2)

    return matches_usersname, matches_url, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity


def tg_message_time(div_message):
    information = div_message.find("div", class_="tgme_widget_message_info")
    time_tag = information.find("time") if information is not None else None
    if time_tag is None or not time_tag.get("datetime"):
        raise ValueError("Telegram message has no timestamp")
    message_time = datetime.fromisoformat(time_tag["datetime"])
    if message_time.utcoffset() is None:
        raise ValueError("Telegram message timestamp has no timezone")
    message_time = message_time.astimezone(IRAN_TIMEZONE)
    now = datetime.now(IRAN_TIMEZONE)
    return message_time, now, now - message_time


def tg_message_text(div_message, content_extracter):
    message = div_message.find("div", class_="tgme_widget_message_text")
    if message is None:
        return ""
    if content_extracter not in ("url", "config"):
        raise ValueError("Content extractor must be 'url' or 'config'")
    # Preserve boundaries between messages/lines without pretty-print whitespace
    # inside inline code. Include hrefs only for URL/channel discovery.
    content = BeautifulSoup(str(message), "html.parser")
    for line_break in content.find_all("br"):
        line_break.replace_with("\n")
    for block in content.find_all(("p", "div", "pre", "code")):
        block.append("\n")
    text = content.get_text().strip()
    if content_extracter == "url":
        links = [link["href"] for link in message.find_all("a", href=True)]
        text = "\n".join([text, *links])
    return text


def tg_username_extract(url):
    # Match the full hostname: t.me.evil.example is not a Telegram domain.
    candidate = url if "://" in url else "https://" + url
    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").lower().removeprefix("www.")
    if parsed.scheme.lower() not in ("http", "https") or hostname not in TELEGRAM_DOMAINS:
        raise ValueError("Not a Telegram URL")
    segments = parsed.path.strip("/").split("/")
    if segments[0] == "s":
        segments = segments[1:]
    if not segments or not re.fullmatch(r"[a-zA-Z0-9_+-]+", segments[0]):
        raise ValueError("Telegram URL has no username")
    return segments[0]



def subscription_origin(url):
    """Distinguish collector channel feeds from independent subscriptions."""
    parsed = urlsplit(url)
    path_parts = parsed.path.strip("/").split("/")
    repositories = {
        DEFAULT_REPOSITORY.lower(),
        os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY).lower(),
        "soroushmirzaei/telegram-configs-collector",
    }
    repository = "/".join(path_parts[:2]).lower()
    if parsed.hostname == "raw.githubusercontent.com" and repository in repositories:
        return "channels" if "channels" in path_parts[2:] else "internal"
    return "external"


def html_content(html_address):
    return BeautifulSoup(fetch_text(html_address), "html.parser").get_text()


def decode_string(content):
    return decode_subscription(content)


def decode_vmess(vmess_config):
    try:
        parameters = vmess_parameters(vmess_config)
        parameters["ps"] = "VMESS"
        return encode_vmess(parameters)
    except (ValueError, TypeError, AttributeError):
        return None


def remove_duplicate_modified(array_configuration):
    return deduplicate_configs(array_configuration)


def remove_duplicate(shadow_array, trojan_array, vmess_array, vless_array,
                     reality_array, tuic_array, hysteria_array, juicity_array,
                     vmess_decode_dedup=True):
    arrays = [shadow_array, trojan_array, vmess_array, vless_array,
              reality_array, tuic_array, hysteria_array, juicity_array]
    unique = [list(dict.fromkeys(array)) for array in arrays]
    if vmess_decode_dedup:
        unique[2] = list(dict.fromkeys(
            decoded for config in unique[2] if (decoded := decode_vmess(config)) is not None
        ))
    return tuple(unique)


def modify_config(shadow_array, trojan_array, vmess_array, vless_array, reality_array, tuic_array, hysteria_array, check_port_connection = True):
    # Checkout connectivity and modify title and protocol type address and resolve IP address
    shadow_array, shadow_tls_array, shadow_non_tls_array, shadow_tcp_array, shadow_ws_array, shadow_http_array, shadow_grpc_array = check_modify_config(array_configuration = shadow_array, protocol_type = "SHADOWSOCKS", check_connection = check_port_connection)
    trojan_array, trojan_tls_array, trojan_non_tls_array, trojan_tcp_array, trojan_ws_array, trojan_http_array, trojan_grpc_array = check_modify_config(array_configuration = trojan_array, protocol_type = "TROJAN", check_connection = check_port_connection)
    vmess_array, vmess_tls_array, vmess_non_tls_array, vmess_tcp_array, vmess_ws_array, vmess_http_array, vmess_grpc_array = check_modify_config(array_configuration = vmess_array, protocol_type = "VMESS", check_connection = check_port_connection)
    vless_array, vless_tls_array, vless_non_tls_array, vless_tcp_array, vless_ws_array, vless_http_array, vless_grpc_array = check_modify_config(array_configuration = vless_array, protocol_type = "VLESS", check_connection = check_port_connection)
    reality_array, reality_tls_array, reality_non_tls_array, reality_tcp_array, reality_ws_array, reality_http_array, reality_grpc_array = check_modify_config(array_configuration = reality_array, protocol_type = "REALITY", check_connection = check_port_connection)
    tuic_array, _, _, _, _, _, _ = check_modify_config(array_configuration = tuic_array, protocol_type = "TUIC", check_connection = False)
    hysteria_array, _, _, _, _, _, _ = check_modify_config(array_configuration = hysteria_array, protocol_type = "HYSTERIA", check_connection = False)

    # Initialize security and netowrk array
    tls_array = list()
    non_tls_array = list()

    tcp_array = list()
    ws_array = list()
    http_array = list()
    grpc_array = list()

    for array in [shadow_tls_array, trojan_tls_array, vmess_tls_array, vless_tls_array, reality_tls_array]:
        tls_array.extend(array)
    for array in [shadow_non_tls_array, trojan_non_tls_array, vmess_non_tls_array, vless_non_tls_array, reality_non_tls_array]:
        non_tls_array.extend(array)

    for array in [shadow_tcp_array, trojan_tcp_array, vmess_tcp_array, vless_tcp_array, reality_tcp_array]:
        tcp_array.extend(array)
    for array in [shadow_ws_array, trojan_ws_array, vmess_ws_array, vless_ws_array, reality_ws_array]:
        ws_array.extend(array)
    for array in [shadow_http_array, trojan_http_array, vmess_http_array, vless_http_array, reality_http_array]:
        http_array.extend(array)
    for array in [shadow_grpc_array, trojan_grpc_array, vmess_grpc_array, vless_grpc_array, reality_grpc_array]:
        grpc_array.extend(array)

    return shadow_array, trojan_array, vmess_array, vless_array, reality_array, tuic_array, hysteria_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array


def create_title(title, port):
    identifier = str(uuid.uuid4())

    # Define configurations based on protocol
    reality_config_title = f"vless://{identifier}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    vless_config_title = f"vless://{identifier}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    vmess_config_title = {"add":"127.0.0.1","aid":"0","host":"","id":identifier,"net":"tcp","path":"",
                          "port":port,"ps":title,"scy":"auto","sni":"","tls":"","type":"","v":"2"}
    vmess_config_title = json.dumps(vmess_config_title)
    vmess_config_title = base64.b64encode(vmess_config_title.encode('utf-8')).decode('utf-8')
    vmess_config_title = f'vmess://{vmess_config_title}'
    trojan_config_title = f"trojan://{identifier}@127.0.0.1:{port}?security=tls&type=tcp#{title}"
    shadowsocs_uuid = base64.b64encode(f"none:{identifier}".encode('utf-8')).decode('utf-8')
    shadowsocks_config_title = f"ss://{shadowsocs_uuid}@127.0.0.1:{port}#{title}"

    return reality_config_title, vless_config_title, vmess_config_title, trojan_config_title, shadowsocks_config_title


def collect_configs(last_update_datetime, current_datetime_update):
    refresh_geoip_database()
    jalali_current_datetime_update = jdatetime.datetime.fromgregorian(datetime=current_datetime_update)
    reset_outputs = should_reset_outputs(jalali_current_datetime_update)
    if reset_outputs:
        # Fetch a wider window now, but only clear feeds after successful collection.
        last_update_datetime -= timedelta(days=3)

    # Load telegram channels usernames
    telegram_channels = json_load('telegram channels.json')

    # Initial channels messages array
    channel_messages_array = list()
    removed_channel_array = list()
    channel_check_messages_array = list()

    # Iterate over all public telegram chanels and store twenty latest messages
    for channel_user in telegram_channels:
        try:
            print(f'{channel_user}')
            # Iterate over Telegram channels to Retrieve channel messages and extend to array
            div_messages = tg_channel_messages(channel_user)

            # Append destroyed Telegram channels
            if len(div_messages) == 0:
                removed_channel_array.append(channel_user)
            # Check configuation Telegram channels
            channel_check_messages_array.append((channel_user, div_messages))

            for div_message in div_messages:
                datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
                if datetime_object > last_update_datetime:
                    print(f"\t{datetime_object.strftime('%a, %d %b %Y %X %Z')}")
                    channel_messages_array.append((channel_user, div_message))
        except (requests.RequestException, ValueError, AttributeError) as exc:
            LOGGER.warning("Skipping Telegram channel %s: %s", channel_user, exc)
            continue

    # Print out total new messages counter
    print(f"\nTotal New Messages From {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(channel_messages_array)}\n")


    # Initial arrays for protocols
    array_usernames = list()
    array_url = list()
    array_shadowsocks = list()
    array_trojan = list()
    array_vmess = list()
    array_vless = list()
    array_reality = list()
    array_tuic = list()
    array_hysteria = list()
    array_juicity = list()

    for channel_user, message in channel_messages_array:
        try:
            # Iterate over channel messages to extract text content
            url_text_content = tg_message_text(message, 'url')
            config_text_content = tg_message_text(message, 'config')
            # Iterate over each message to extract configuration protocol types and subscription links
            matches_username, matches_url, _ , _ , _ , _ , _ , _ , _ , _ = find_matches(url_text_content)
            _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)

            # Extend protocol type arrays and subscription link array
            array_usernames.extend([element.lower() for element in matches_username if len(element) >= 5])
            array_url.extend(matches_url)
            array_shadowsocks.extend(matches_shadowsocks)
            array_trojan.extend(matches_trojan)
            array_vmess.extend(matches_vmess)
            array_vless.extend(matches_vless)
            array_reality.extend(matches_reality)
            array_tuic.extend(matches_tuic)
            array_hysteria.extend(matches_hysteria)
            array_juicity.extend(matches_juicity)

        except (ValueError, TypeError, AttributeError) as exc:
            LOGGER.warning("Skipping a malformed Telegram message: %s", exc)
            continue


    # Initialize Telegram channels list without configuration
    channel_without_config = set()

    for channel_user, messages in channel_check_messages_array:
        # Initialize Channel Configs Counter
        total_config = 0

        for message in messages:
            try:
                # Iterate over channel messages to extract text content
                url_text_content = tg_message_text(message, 'url')
                config_text_content = tg_message_text(message, 'config')
                # Iterate over each message to extract configuration protocol types and subscription links
                matches_username, matches_url, _ , _ , _ , _ , _ , _ , _ , _ = find_matches(url_text_content)
                _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)
                total_config = total_config + len(matches_shadowsocks) + len(matches_trojan) + len(matches_vmess) + len(matches_vless) + len(matches_reality) + len(matches_tuic) + len(matches_hysteria) + len(matches_juicity)

            except (ValueError, TypeError, AttributeError) as exc:
                LOGGER.warning("Skipping a malformed Telegram message: %s", exc)
                continue

        if total_config == 0:
            channel_without_config.add(channel_user)




    # Split Telegram usernames and subscription url links
    tg_username_list = set()
    url_subscription_links = set()

    for url in array_url:
        try:
            tg_user = tg_username_extract(url)
            if tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user)>=5:
                tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
                tg_username_list.add(tg_user.lower())
        except:
            url_subscription_links.add(url.split("\"")[0])
            continue

    for index, tg_user in enumerate(array_usernames):
        tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
        array_usernames[index] = tg_user


    # The supplemental source is optional; a temporary outage must not stop collection.
    tg_username_list.update(array_usernames)
    try:
        proxy_channels = json.loads(fetch_text(
            "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/telegram%20channels.json"
        ))
        if not isinstance(proxy_channels, list) or not all(isinstance(channel, str) for channel in proxy_channels):
            raise ValueError("Supplemental channel list must contain usernames")
        tg_username_list.update(proxy_channels)
    except (requests.RequestException, ValueError) as exc:
        LOGGER.warning("Skipping the supplemental channel source: %s", exc)


    # Subtract and get new telegram channels
    new_telegram_channels = tg_username_list.difference(telegram_channels)

    # Initial channels messages array
    new_channel_messages = list()
    invalid_array_channels = json_load('invalid telegram channels.json')
    invalid_array_channels = set(invalid_array_channels)

    # Iterate over all public telegram chanels and store twenty latest messages
    for channel_user in new_telegram_channels:
        if channel_user not in invalid_array_channels:
            try:
                print(f'{channel_user}')
                # Iterate over Telegram channels to Retrieve channel messages and extend to array
                div_messages = tg_channel_messages(channel_user)
                channel_messages = list()
                for div_message in div_messages:
                    datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
                    print(f"\t{datetime_object.strftime('%a, %d %b %Y %X %Z')}")
                    channel_messages.append(div_message)
                new_channel_messages.append((channel_user, channel_messages))
            except:
                continue
        else:
            continue

    # Messages Counter
    print(f"\nTotal New Messages From New Channels {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(new_channel_messages)}\n")


    # Initial arrays for protocols
    new_array_shadowsocks = list()
    new_array_trojan = list()
    new_array_vmess = list()
    new_array_vless = list()
    new_array_reality = list()
    new_array_tuic = list()
    new_array_hysteria = list()
    new_array_juicity = list()

    # Initialize array for channelswith configuration contents
    new_array_channels = set()

    for channel, messages in new_channel_messages:
        # Set Iterator to estimate each channel configurations
        total_config = 0
        new_array_url = set()
        new_array_usernames = set()

        for message in messages:
            try:
                # Iterate over channel messages to extract text content
                url_text_content = tg_message_text(message, 'url')
                config_text_content = tg_message_text(message, 'config')
                # Iterate over each message to extract configuration protocol types and subscription links
                matches_username, matches_url, _ , _ , _ , _ , _ , _ , _ , _ = find_matches(url_text_content)
                _ , _ , matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = find_matches(config_text_content)
                total_config = total_config + len(matches_shadowsocks) + len(matches_trojan) + len(matches_vmess) + len(matches_vless) + len(matches_reality) + len(matches_tuic) + len(matches_hysteria) + len(matches_juicity)

                # Extend protocol type arrays and subscription link array
                new_array_usernames.update([element.lower() for element in matches_username if len(element) >= 5])
                new_array_url.update(matches_url)
                new_array_shadowsocks.extend(matches_shadowsocks)
                new_array_trojan.extend(matches_trojan)
                new_array_vmess.extend(matches_vmess)
                new_array_vless.extend(matches_vless)
                new_array_reality.extend(matches_reality)
                new_array_tuic.extend(matches_tuic)
                new_array_hysteria.extend(matches_hysteria)
                new_array_juicity.extend(matches_juicity)

            except (ValueError, TypeError, AttributeError) as exc:
                LOGGER.warning("Skipping a malformed Telegram message: %s", exc)
                continue

        # Append to channels that conatins configurations
        if total_config != 0:
            new_array_channels.add(channel)
        else:
            invalid_array_channels.add(channel)

        # Split Telegram usernames and subscription url links
        tg_username_list_new = set()

        for url in new_array_url:
            try:
                tg_user = tg_username_extract(url)
                if tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user)>=5:
                    tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
                    tg_username_list_new.add(tg_user.lower())
            except:
                url_subscription_links.add(url.split("\"")[0])
                continue

        new_array_usernames = list(new_array_usernames)
        for index, tg_user in enumerate(new_array_usernames):
            tg_user = ''.join([element for element in list(tg_user) if element in string.ascii_letters + string.digits + '_'])
            new_array_usernames[index] = tg_user

        # Subtract and get new telegram channels
        tg_username_list_new.update([element.lower() for element in new_array_usernames])
        tg_username_list_new = tg_username_list_new.difference(telegram_channels)
        tg_username_list_new = tg_username_list_new.difference(new_telegram_channels)
        updated_new_channel = set(list(map(lambda element : element[0], new_channel_messages)))
        tg_username_list_new = tg_username_list_new.difference(updated_new_channel)

        # Iterate over all public telegram chanels and store twenty latest messages
        for channel_user in tg_username_list_new:
            if channel_user not in invalid_array_channels:
                try:
                    print(f'{channel_user}')
                    # Iterate over Telegram channels to Retrieve channel messages and extend to array
                    div_messages = tg_channel_messages(channel_user)
                    channel_messages = list()
                    for div_message in div_messages:
                        datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
                        #print(f"\t{datetime_object.strftime('%a, %d %b %Y %X %Z')}")
                        channel_messages.append(div_message)
                    #new_channel_messages.append((channel_user, channel_messages))
                except:
                    continue
            else:
                continue


    # Extend new configurations into list previous ones
    array_shadowsocks.extend(new_array_shadowsocks)
    array_trojan.extend(new_array_trojan)
    array_vmess.extend(new_array_vmess)
    array_vless.extend(new_array_vless)
    array_reality.extend(new_array_reality)
    array_tuic.extend(new_array_tuic)
    array_hysteria.extend(new_array_hysteria)
    array_juicity.extend(new_array_juicity)

    print("New Telegram Channels Found")
    for channel in new_array_channels:
        print('\t{value}'.format(value = channel))

    print("Destroyed Telegram Channels Found")
    for channel in removed_channel_array:
        print('\t{value}'.format(value = channel))

    print("No Config Telegram Channels Found")
    for channel in channel_without_config:
        print('\t{value}'.format(value = channel))

    # Extend new channels into previous channels
    telegram_channels.extend(new_array_channels)
    #telegram_channels = [channel for channel in telegram_channels if channel not in removed_channel_array and channel not in channel_without_config]
    telegram_channels = [channel for channel in telegram_channels if channel not in removed_channel_array]
    telegram_channels = list(dict.fromkeys(telegram_channels))
    telegram_channels = sorted(telegram_channels)

    invalid_telegram_channels = list(dict.fromkeys(invalid_array_channels))
    invalid_telegram_channels = sorted(invalid_telegram_channels)

    # Update url subscription links
    url_subscription_links = list(url_subscription_links)

    new_tg_username_list = set()
    new_url_subscription_links = set()

    for url in url_subscription_links:
        try:
            tg_user = tg_username_extract(url)
            if tg_user not in ['proxy', 'img', 'emoji', 'joinchat']:
                new_tg_username_list.add(tg_user.lower())
        except:
            new_url_subscription_links.add(url.split("\"")[0])
            continue

    # Chnage type of url subscription links into list to be hashable
    new_url_subscription_links = list(new_url_subscription_links)


    accept_chars = ['sub', 'subscribe', 'token', 'workers', 'worker', 'dev', 'txt', 'vmess', 'vless', 'reality', 'trojan', 'shadowsocks']
    avoid_chars = ['github', 'githubusercontent', 'gist', 'git', 'google', 'play', 'apple', 'microsoft']

    new_subscription_links = set()

    for index, element in enumerate(new_url_subscription_links):
        acc_cond = [char in element.lower() for char in accept_chars]
        avoid_cond = [char in element.lower() for char in avoid_chars]
        if any(acc_cond):
            if not any(avoid_cond):
                new_subscription_links.add(element)


    # Load subscription links
    subscription_links = json_load('subscription links.json')
    # subscription_links.extend(new_subscription_links)

    # Initial links contents array decoded content array
    array_links_content = list()
    array_links_content_decoded = list()

    raw_array_links_content = list()
    raw_array_links_content_decoded = list()

    channel_array_links_content = list()
    channel_array_links_content_decoded = list()

    for url_link in subscription_links:
        try:
            # Retrieve subscription link content
            links_content = html_content(url_link)
            array_links_content.append((url_link, links_content))
            origin = subscription_origin(url_link)
            if origin == "external":
                raw_array_links_content.append((url_link, links_content))
            elif origin == "channels":
                channel_array_links_content.append((url_link, links_content))
        except requests.RequestException as exc:
            LOGGER.warning("Skipping an unavailable subscription source: %s", exc)
            continue


    # Separate encoded and unencoded strings
    decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), array_links_content))
    # Separate encoded and unencoded strings
    raw_decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), raw_array_links_content))
    # Separate encoded and unencoded strings
    channel_decoded_contents = list(map(lambda element : (element[0], decode_string(element[1])), channel_array_links_content))

    for url_link, content in decoded_contents:
        try:
            # Split each link contents into array and split by lines
            link_contents = content.splitlines()
            link_contents = [element for element in link_contents if element not in ['\n','\t','']]
            # Iterate over link contents to subtract titles
            for index, element in enumerate(link_contents):
                link_contents[index] = re.sub(r"#[^#]+$", "", element)
            array_links_content_decoded.append((url_link, link_contents))
        except:
            continue


    for url_link, content in raw_decoded_contents:
        try:
            # Split each link contents into array and split by lines
            link_contents = content.splitlines()
            link_contents = [element for element in link_contents if element not in ['\n','\t','']]
            # Iterate over link contents to subtract titles
            for index, element in enumerate(link_contents):
                link_contents[index] = re.sub(r"#[^#]+$", "", element)
            raw_array_links_content_decoded.append((url_link, link_contents))
        except:
            continue


    for url_link, content in channel_decoded_contents:
        try:
            # Split each link contents into array and split by lines
            link_contents = content.splitlines()
            link_contents = [element for element in link_contents if element not in ['\n','\t','']]
            # Iterate over link contents to subtract titles
            for index, element in enumerate(link_contents):
                link_contents[index] = re.sub(r"#[^#]+$", "", element)
            channel_array_links_content_decoded.append((url_link, link_contents))
        except:
            continue


    new_subscription_urls = set()

    matches_usernames = list()
    matches_url = list()
    matches_shadowsocks = list()
    matches_trojan = list()
    matches_vmess = list()
    matches_vless = list()
    matches_reality = list()
    matches_tuic = list()
    matches_hysteria = list()
    matches_juicity = list()

    raw_matches_usernames = list()
    raw_matches_url = list()
    raw_matches_shadowsocks = list()
    raw_matches_trojan = list()
    raw_matches_vmess = list()
    raw_matches_vless = list()
    raw_matches_reality = list()
    raw_matches_tuic = list()
    raw_matches_hysteria = list()
    raw_matches_juicity = list()

    channel_matches_usernames = list()
    channel_matches_url = list()
    channel_matches_shadowsocks = list()
    channel_matches_trojan = list()
    channel_matches_vmess = list()
    channel_matches_vless = list()
    channel_matches_reality = list()
    channel_matches_tuic = list()
    channel_matches_hysteria = list()
    channel_matches_juicity = list()

    for url_link, content in array_links_content_decoded:
        # Merge all subscription links content and find all protocols matches base on protocol pattern
        content_merged = "\n".join(content)
        match_user, match_url, match_socks, match_trojan, match_vmess, match_vless, match_reality, match_tuic, match_hysteria, match_juicity = find_matches(content_merged)

        if len(match_socks) + len(match_trojan) + len(match_vmess) + len(match_vless) + len(match_reality) + len(match_tuic) + len(match_hysteria) + len(match_juicity) != 0:
            new_subscription_urls.add(url_link)

        matches_usernames.extend(match_user)
        matches_url.extend(match_url)
        matches_shadowsocks.extend(match_socks)
        matches_trojan.extend(match_trojan)
        matches_vmess.extend(match_vmess)
        matches_vless.extend(match_vless)
        matches_reality.extend(match_reality)
        matches_tuic.extend(match_tuic)
        matches_hysteria.extend(match_hysteria)
        matches_juicity.extend(match_juicity)

    for url_link, content in raw_array_links_content_decoded:
        # Merge all subscription links content and find all protocols matches base on protocol pattern
        raw_content_merged = "\n".join(content)
        match_user, match_url, match_socks, match_trojan, match_vmess, match_vless, match_reality, match_tuic, match_hysteria, match_juicity = find_matches(raw_content_merged)

        raw_matches_usernames.extend(match_user)
        raw_matches_url.extend(match_url)
        raw_matches_shadowsocks.extend(match_socks)
        raw_matches_trojan.extend(match_trojan)
        raw_matches_vmess.extend(match_vmess)
        raw_matches_vless.extend(match_vless)
        raw_matches_reality.extend(match_reality)
        raw_matches_tuic.extend(match_tuic)
        raw_matches_hysteria.extend(match_hysteria)
        raw_matches_juicity.extend(match_juicity)

    for url_link, content in channel_array_links_content_decoded:
        # Merge all subscription links content and find all protocols matches base on protocol pattern
        raw_content_merged = "\n".join(content)
        match_user, match_url, match_socks, match_trojan, match_vmess, match_vless, match_reality, match_tuic, match_hysteria, match_juicity = find_matches(raw_content_merged)

        channel_matches_usernames.extend(match_user)
        channel_matches_url.extend(match_url)
        channel_matches_shadowsocks.extend(match_socks)
        channel_matches_trojan.extend(match_trojan)
        channel_matches_vmess.extend(match_vmess)
        channel_matches_vless.extend(match_vless)
        channel_matches_reality.extend(match_reality)
        channel_matches_tuic.extend(match_tuic)
        channel_matches_hysteria.extend(match_hysteria)
        channel_matches_juicity.extend(match_juicity)

    # Save New Subscription Links
    # with open('./subscription links.json', 'w') as subscription_file:
    #    json.dump(sorted(new_subscription_urls), subscription_file, indent = 4)








    # Remove Duplicate Configurations
    configs_list_array = [array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria]
    array_removed_duplicate_list_configurations = list()

    if not any(configs_list_array) and not any((array_juicity, matches_juicity, raw_matches_juicity, channel_matches_juicity)):
        raise RuntimeError("No configurations collected; refusing to replace existing feeds")

    prepare_output_directories()
    Path("splitted/no-match").write_text("#Non-Adaptive Configurations\n", encoding="utf-8")

    for array in configs_list_array:
        print(f"Before Removing Duplicates : {len(array)}", end = '\t')
        array = remove_duplicate_modified(array)
        print(f"After Removing Duplicates : {len(array)}")
        array_removed_duplicate_list_configurations.append(array)

    # Dedicate removed array of the list of elements
    array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria = array_removed_duplicate_list_configurations


    # Remove duplicate configurations of telegram channels and subscription links contents
    array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, array_juicity = remove_duplicate(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, array_juicity)
    matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = remove_duplicate(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity)
    raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, raw_matches_juicity = remove_duplicate(raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, raw_matches_juicity)
    channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, channel_matches_juicity = remove_duplicate(channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, channel_matches_juicity)

    # Checkout connectivity and modify title and protocol type address and resolve IP address
    array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality,  array_tuic, array_hysteria, array_tls, array_non_tls, array_tcp, array_ws, array_http, array_grpc = modify_config(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria)
    matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_tls, matches_non_tls, matches_tcp, matches_ws, matches_http, matches_grpc = modify_config(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria)
    raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, raw_matches_tls, raw_matches_non_tls, raw_matches_tcp, raw_matches_ws, raw_matches_http, raw_matches_grpc = modify_config(raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, check_port_connection = False)
    channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, channel_matches_tls, channel_matches_non_tls, channel_matches_tcp, channel_matches_ws, channel_matches_http, channel_matches_grpc = modify_config(channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, check_port_connection = True)


    # Extend channel subscription links contents to telegram channel contents
    array_shadowsocks_channels = array_shadowsocks.copy()
    array_trojan_channels = array_trojan.copy()
    array_vmess_channels = array_vmess.copy()
    array_vless_channels = array_vless.copy()
    array_reality_channels = array_reality.copy()
    array_tuic_channels = array_tuic.copy()
    array_hysteria_channels = array_hysteria.copy()
    array_juicity_channels = array_juicity.copy()

    array_shadowsocks_channels.extend(channel_matches_shadowsocks)
    array_trojan_channels.extend(channel_matches_trojan)
    array_vmess_channels.extend(channel_matches_vmess)
    array_vless_channels.extend(channel_matches_vless)
    array_reality_channels.extend(channel_matches_reality)
    array_tuic_channels.extend(channel_matches_tuic)
    array_hysteria_channels.extend(channel_matches_hysteria)
    array_juicity_channels.extend(channel_matches_juicity)

    # Remove duplicate configurations after modifying telegram channels and subscription links contents
    array_shadowsocks_channels, array_trojan_channels, array_vmess_channels, array_vless_channels, array_reality_channels, array_tuic_channels, array_hysteria_channels, array_juicity_channels = remove_duplicate(array_shadowsocks_channels, array_trojan_channels, array_vmess_channels, array_vless_channels, array_reality_channels, array_tuic_channels, array_hysteria_channels, array_juicity_channels, vmess_decode_dedup = False)
    channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, channel_matches_juicity = remove_duplicate(channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria, channel_matches_juicity, vmess_decode_dedup = False)

    # Extend channel subscription links contents to telegram channel contents based on networks and security
    array_tls_channels = array_tls.copy()
    array_non_tls_channels = array_non_tls.copy()
    array_tcp_channels = array_tcp.copy()
    array_ws_channels = array_ws.copy()
    array_http_channels = array_http.copy()
    array_grpc_channels = array_grpc.copy()

    array_tls_channels.extend(channel_matches_tls)
    array_non_tls_channels.extend(channel_matches_non_tls)
    array_tcp_channels.extend(channel_matches_tcp)
    array_ws_channels.extend(channel_matches_ws)
    array_http_channels.extend(channel_matches_http)
    array_grpc_channels.extend(channel_matches_grpc)

    array_tls_channels = list(dict.fromkeys(array_tls_channels))
    array_non_tls_channels = list(dict.fromkeys(array_non_tls_channels))
    array_tcp_channels = list(dict.fromkeys(array_tcp_channels))
    array_ws_channels = list(dict.fromkeys(array_ws_channels))
    array_http_channels = list(dict.fromkeys(array_http_channels))
    array_grpc_channels = list(dict.fromkeys(array_grpc_channels))


    # Extend subscription links contents to telegram channel contents
    array_shadowsocks.extend(matches_shadowsocks)
    array_trojan.extend(matches_trojan)
    array_vmess.extend(matches_vmess)
    array_vless.extend(matches_vless)
    array_reality.extend(matches_reality)
    array_tuic.extend(matches_tuic)
    array_hysteria.extend(matches_hysteria)
    array_juicity.extend(matches_juicity)

    # Remove duplicate configurations after modifying telegram channels and subscription links contents
    array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, array_juicity = remove_duplicate(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, array_juicity, vmess_decode_dedup = False)
    matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity = remove_duplicate(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, matches_juicity, vmess_decode_dedup = False)
    raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, raw_matches_juicity = remove_duplicate(raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, raw_matches_juicity, vmess_decode_dedup = False)

    # Extend subscription links contents to telegram channel contents
    array_tls.extend(matches_tls)
    array_non_tls.extend(matches_non_tls)
    array_tcp.extend(matches_tcp)
    array_ws.extend(matches_ws)
    array_http.extend(matches_http)
    array_grpc.extend(matches_grpc)

    # Remove duplicate configurations after modifying telegram channels and subscription links contents
    array_tls = list(dict.fromkeys(array_tls))
    array_non_tls = list(dict.fromkeys(array_non_tls))
    array_tcp = list(dict.fromkeys(array_tcp))
    array_ws = list(dict.fromkeys(array_ws))
    array_http = list(dict.fromkeys(array_http))
    array_grpc = list(dict.fromkeys(array_grpc))

    raw_matches_tls = list(dict.fromkeys(raw_matches_tls))
    raw_matches_non_tls = list(dict.fromkeys(raw_matches_non_tls))
    raw_matches_tcp = list(dict.fromkeys(raw_matches_tcp))
    raw_matches_ws = list(dict.fromkeys(raw_matches_ws))
    raw_matches_http = list(dict.fromkeys(raw_matches_http))
    raw_matches_grpc = list(dict.fromkeys(raw_matches_grpc))


    # Remove Duplicate Configurations
    array_list_configurations = [array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria]
    array_removed_duplicate_list_configurations = list()

    for array in array_list_configurations:
        print(f"Before Removing Duplicates : {len(array)}", end = '\t')
        array = remove_duplicate_modified(array)
        print(f"After Removing Duplicates : {len(array)}")
        array_removed_duplicate_list_configurations.append(array)

    # Dedicate removed array of the list of elements
    array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tuic, array_hysteria, matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tuic, matches_hysteria, raw_matches_shadowsocks, raw_matches_trojan, raw_matches_vmess, raw_matches_vless, raw_matches_reality, raw_matches_tuic, raw_matches_hysteria, channel_matches_shadowsocks, channel_matches_trojan, channel_matches_vmess, channel_matches_vless, channel_matches_reality, channel_matches_tuic, channel_matches_hysteria = array_removed_duplicate_list_configurations


    if not any(array_removed_duplicate_list_configurations) and not any((array_juicity, matches_juicity, raw_matches_juicity, channel_matches_juicity)):
        raise RuntimeError("No usable configurations collected; refusing to replace existing feeds")

    if reset_outputs:
        reset_collected_configs()

    # Combine all configurations into one mixed configuration array and shuffle
    array_mixed = array_shadowsocks + array_trojan + array_vmess + array_vless + array_reality

    chunks = split_configs(array_mixed)


    # Define update date and time based on Iran timezone and calendar
    datetime_update = jdatetime.datetime.fromgregorian(datetime=current_datetime_update)
    datetime_update_str = datetime_update.strftime("\U0001F504 LATEST-UPDATE \U0001F4C5 %a-%d-%B-%Y \U0001F551 %H:%M").upper()
    # Define update time based on protocol type
    reality_update, vless_update, vmess_update, trojan_update, shadowsocks_update = create_title(datetime_update_str, port = 1080)

    # Define develooper sign
    dev_sign = "\U0001F468\U0001F3FB\u200D\U0001F4BB DEVELOPED-BY SOROUSH-MIRZAEI \U0001F4CC FOLLOW-CONTACT SYDSRSMRZ"
    # Define develooper based on protocol type
    reality_dev_sign, vless_dev_sign, vmess_dev_sign, trojan_dev_sign, shadowsocks_dev_sign = create_title(dev_sign, port = 8080)

    # Define Advertisement row
    adv_bool = True
    adv_sign = "\U0001F916 TELEGRAM-CHANNEL \U0001F31F ARTIFICIAL-INTELLIGENCE \U0001F5A5 @NEUROVANCE \U0001F9E0"
    # Define develooper based on protocol type
    reality_adv_sign, vless_adv_sign, vmess_adv_sign, trojan_adv_sign, shadowsocks_adv_sign = create_title(adv_sign, port = 2080)

    # Define Donating row
    dnt_bool = True
    dnt_sign = "\U0001F6E1 TELEGRAM-CHANNEL \U0001F510 MTPROTO-PROXY \U0001F30D @NEXUPROXY \U0001F4E1"
    # Define develooper based on protocol type
    reality_dnt_sign, vless_dnt_sign, vmess_dnt_sign, trojan_dnt_sign, shadowsocks_dnt_sign = create_title(dnt_sign, port = 3080)


    # Save configurations based on splitted and chunks
    for i in range(0, 10):
        if i < len(chunks):
            with open(f"./splitted/mixed-{i}", "w", encoding="utf-8") as file:
                chunks[i].insert(0, trojan_update)
                if adv_bool:
                    chunks[i].insert(1, trojan_adv_sign)
                if dnt_bool:
                    chunks[i].insert(2, trojan_dnt_sign)
                chunks[i].append(trojan_dev_sign)
                file.write(base64.b64encode("\n".join(chunks[i]).encode("utf-8")).decode("utf-8"))
        else:
            with open(f"./splitted/mixed-{i}", "w", encoding="utf-8") as file:
                file.write("")


    # Create dictionary type of country based configuration list
    country_based_configs_dict = create_country(array_mixed)

    for country in country_based_configs_dict.keys():
        country_based_configs_dict[country].insert(0, trojan_update)
        if adv_bool:
            country_based_configs_dict[country].insert(1, trojan_adv_sign)
        if dnt_bool:
            country_based_configs_dict[country].insert(2, trojan_dnt_sign)
        country_based_configs_dict[country].append(trojan_dev_sign)
        if not os.path.exists('./countries'):
            os.mkdir('./countries')
        if not os.path.exists(f'./countries/{country}'):
            os.mkdir(f'./countries/{country}')
        with open(f'./countries/{country}/mixed', "w", encoding="utf-8") as file:
            file.write(base64.b64encode("\n".join(country_based_configs_dict[country]).encode("utf-8")).decode("utf-8"))


    # Split and save mixed array based on internet protocol
    array_mixed_ipv4, array_mixed_ipv6 = create_internet_protocol(array_mixed)
    with open("./layers/ipv4", "w", encoding="utf-8") as file:
        array_mixed_ipv4.insert(0, trojan_update)
        if adv_bool:
            array_mixed_ipv4.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_mixed_ipv4.insert(2, trojan_dnt_sign)
        array_mixed_ipv4.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_mixed_ipv4).encode("utf-8")).decode("utf-8"))

    with open("./layers/ipv6", "w", encoding="utf-8") as file:
        array_mixed_ipv6.insert(0, trojan_update)
        if adv_bool:
            array_mixed_ipv6.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_mixed_ipv6.insert(2, trojan_dnt_sign)
        array_mixed_ipv6.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_mixed_ipv6).encode("utf-8")).decode("utf-8"))


    # Save all mixed array and subscription links content
    with open("./splitted/mixed", "w", encoding="utf-8") as file:
        array_mixed.insert(0, trojan_update)
        if adv_bool:
            array_mixed.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_mixed.insert(2, trojan_dnt_sign)
        array_mixed.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_mixed).encode("utf-8")).decode("utf-8"))


    # Decode vmess configs to change title and remove duplicate
    all_subscription_matches = matches_shadowsocks + matches_trojan + matches_vmess + matches_vless + matches_reality
    all_subscription_matches = list(dict.fromkeys(all_subscription_matches))

    # Split and save mixed array based on internet protocol
    array_subscription_ipv4, array_subscription_ipv6 = create_internet_protocol(all_subscription_matches)
    with open("./subscribe/layers/ipv4", "w", encoding="utf-8") as file:
        array_subscription_ipv4.insert(0, trojan_update)
        if adv_bool:
            array_subscription_ipv4.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_subscription_ipv4.insert(2, trojan_dnt_sign)
        array_subscription_ipv4.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_subscription_ipv4).encode("utf-8")).decode("utf-8"))

    with open("./subscribe/layers/ipv6", "w", encoding="utf-8") as file:
        array_subscription_ipv6.insert(0, trojan_update)
        if adv_bool:
            array_subscription_ipv6.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_subscription_ipv6.insert(2, trojan_dnt_sign)
        array_subscription_ipv6.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_subscription_ipv6).encode("utf-8")).decode("utf-8"))

    # Save subscription configurations file
    with open("./splitted/subscribe", "w", encoding="utf-8") as file:
        all_subscription_matches.insert(0, trojan_update)
        if adv_bool:
            all_subscription_matches.insert(1, trojan_adv_sign)
        if dnt_bool:
            all_subscription_matches.insert(2, trojan_dnt_sign)
        all_subscription_matches.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(all_subscription_matches).encode("utf-8")).decode("utf-8"))


    # Decode vmess configs to change title and remove duplicate
    all_channel_matches = array_shadowsocks_channels + array_trojan_channels + array_vmess_channels + array_vless_channels + array_reality_channels
    all_channel_matches = list(dict.fromkeys(all_channel_matches))

    # Split and save mixed array based on internet protocol
    array_channel_ipv4, array_channel_ipv6 = create_internet_protocol(all_channel_matches)
    with open("./channels/layers/ipv4", "w", encoding="utf-8") as file:
        array_channel_ipv4.insert(0, trojan_update)
        if adv_bool:
            array_channel_ipv4.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_channel_ipv4.insert(2, trojan_dnt_sign)
        array_channel_ipv4.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_channel_ipv4).encode("utf-8")).decode("utf-8"))

    with open("./channels/layers/ipv6", "w", encoding="utf-8") as file:
        array_channel_ipv6.insert(0, trojan_update)
        if adv_bool:
            array_channel_ipv6.insert(1, trojan_adv_sign)
        if dnt_bool:
            array_channel_ipv6.insert(2, trojan_dnt_sign)
        array_channel_ipv6.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(array_channel_ipv6).encode("utf-8")).decode("utf-8"))

    # Save channel configurations file
    with open("./splitted/channels", "w", encoding="utf-8") as file:
        all_channel_matches.insert(0, trojan_update)
        if adv_bool:
            all_channel_matches.insert(1, trojan_adv_sign)
        if dnt_bool:
            all_channel_matches.insert(2, trojan_dnt_sign)
        all_channel_matches.append(trojan_dev_sign)
        file.write(base64.b64encode("\n".join(all_channel_matches).encode("utf-8")).decode("utf-8"))


    array_shadowsocks.insert(0, shadowsocks_update)
    array_trojan.insert(0, trojan_update)
    array_vmess.insert(0, vmess_update)
    array_vless.insert(0, vless_update)
    array_reality.insert(0, reality_update)
    array_tuic.insert(0, vless_update)
    array_hysteria.insert(0, vless_update)
    array_juicity.insert(0, vless_update)

    if adv_bool:
        array_shadowsocks.insert(1, shadowsocks_adv_sign)
        array_trojan.insert(1, trojan_adv_sign)
        array_vmess.insert(1, vmess_adv_sign)
        array_vless.insert(1, vless_adv_sign)
        array_reality.insert(1, reality_adv_sign)
        array_tuic.insert(1, vless_adv_sign)
        array_hysteria.insert(1, vless_adv_sign)
        array_juicity.insert(1, vless_adv_sign)

    if dnt_bool:
        array_shadowsocks.insert(2, shadowsocks_dnt_sign)
        array_trojan.insert(2, trojan_dnt_sign)
        array_vmess.insert(2, vmess_dnt_sign)
        array_vless.insert(2, vless_dnt_sign)
        array_reality.insert(2, reality_dnt_sign)
        array_tuic.insert(2, vless_dnt_sign)
        array_hysteria.insert(2, vless_dnt_sign)
        array_juicity.insert(2, vless_dnt_sign)

    array_shadowsocks.append(shadowsocks_dev_sign)
    array_trojan.append(trojan_dev_sign)
    array_vmess.append(vmess_dev_sign)
    array_vless.append(vless_dev_sign)
    array_reality.append(reality_dev_sign)
    array_tuic.append(vless_dev_sign)
    array_hysteria.append(vless_dev_sign)
    array_juicity.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./protocols/shadowsocks", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_shadowsocks).encode("utf-8")).decode("utf-8"))
    with open("./protocols/trojan", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_trojan).encode("utf-8")).decode("utf-8"))
    with open("./protocols/vmess", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_vmess).encode("utf-8")).decode("utf-8"))
    with open("./protocols/vless", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_vless).encode("utf-8")).decode("utf-8"))
    with open("./protocols/reality", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_reality).encode("utf-8")).decode("utf-8"))
    with open("./protocols/tuic", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tuic).encode("utf-8")).decode("utf-8"))
    with open("./protocols/hysteria", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_hysteria).encode("utf-8")).decode("utf-8"))
    with open("./protocols/juicity", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_juicity).encode("utf-8")).decode("utf-8"))

    array_tls.insert(0, vless_update)
    array_non_tls.insert(0, vless_update)
    array_tcp.insert(0, vless_update)
    array_ws.insert(0, vless_update)
    array_http.insert(0, vless_update)
    array_grpc.insert(0, vless_update)

    if dnt_bool:
        array_tls.insert(2, vless_dnt_sign)
        array_non_tls.insert(2, vless_dnt_sign)
        array_tcp.insert(2, vless_dnt_sign)
        array_ws.insert(2, vless_dnt_sign)
        array_http.insert(2, vless_dnt_sign)
        array_grpc.insert(2, vless_dnt_sign)

    array_tls.append(vless_dev_sign)
    array_non_tls.append(vless_dev_sign)
    array_tcp.append(vless_dev_sign)
    array_ws.append(vless_dev_sign)
    array_http.append(vless_dev_sign)
    array_grpc.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./security/tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tls).encode("utf-8")).decode("utf-8"))
    with open("./security/non-tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_non_tls).encode("utf-8")).decode("utf-8"))
    with open("./networks/tcp", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tcp).encode("utf-8")).decode("utf-8"))
    with open("./networks/ws", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_ws).encode("utf-8")).decode("utf-8"))
    with open("./networks/http", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_http).encode("utf-8")).decode("utf-8"))
    with open("./networks/grpc", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_grpc).encode("utf-8")).decode("utf-8"))


    raw_matches_shadowsocks.insert(0, shadowsocks_update)
    raw_matches_trojan.insert(0, trojan_update)
    raw_matches_vmess.insert(0, vmess_update)
    raw_matches_vless.insert(0, vless_update)
    raw_matches_reality.insert(0, reality_update)
    raw_matches_tuic.insert(0, vless_update)
    raw_matches_hysteria.insert(0, vless_update)
    raw_matches_juicity.insert(0, vless_update)

    if adv_bool:
        raw_matches_shadowsocks.insert(1, shadowsocks_adv_sign)
        raw_matches_trojan.insert(1, trojan_adv_sign)
        raw_matches_vmess.insert(1, vmess_adv_sign)
        raw_matches_vless.insert(1, vless_adv_sign)
        raw_matches_reality.insert(1, reality_adv_sign)
        raw_matches_tuic.insert(1, vless_adv_sign)
        raw_matches_hysteria.insert(1, vless_adv_sign)
        raw_matches_juicity.insert(1, vless_adv_sign)

    if dnt_bool:
        raw_matches_shadowsocks.insert(2, shadowsocks_dnt_sign)
        raw_matches_trojan.insert(2, trojan_dnt_sign)
        raw_matches_vmess.insert(2, vmess_dnt_sign)
        raw_matches_vless.insert(2, vless_dnt_sign)
        raw_matches_reality.insert(2, reality_dnt_sign)
        raw_matches_tuic.insert(2, vless_dnt_sign)
        raw_matches_hysteria.insert(2, vless_dnt_sign)
        raw_matches_juicity.insert(2, vless_dnt_sign)

    raw_matches_shadowsocks.append(shadowsocks_dev_sign)
    raw_matches_trojan.append(trojan_dev_sign)
    raw_matches_vmess.append(vmess_dev_sign)
    raw_matches_vless.append(vless_dev_sign)
    raw_matches_reality.append(reality_dev_sign)
    raw_matches_tuic.append(vless_dev_sign)
    raw_matches_hysteria.append(vless_dev_sign)
    raw_matches_juicity.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./subscribe/protocols/shadowsocks", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_shadowsocks).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/trojan", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_trojan).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/vmess", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_vmess).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/vless", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_vless).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/reality", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_reality).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/tuic", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_tuic).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/hysteria", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_hysteria).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/protocols/juicity", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_juicity).encode("utf-8")).decode("utf-8"))


    raw_matches_tls.insert(0, vless_update)
    raw_matches_non_tls.insert(0, vless_update)
    raw_matches_tcp.insert(0, vless_update)
    raw_matches_ws.insert(0, vless_update)
    raw_matches_http.insert(0, vless_update)
    raw_matches_grpc.insert(0, vless_update)

    if adv_bool:
        raw_matches_tls.insert(1, vless_adv_sign)
        raw_matches_non_tls.insert(1, vless_adv_sign)
        raw_matches_tcp.insert(1, vless_adv_sign)
        raw_matches_ws.insert(1, vless_adv_sign)
        raw_matches_http.insert(1, vless_adv_sign)
        raw_matches_grpc.insert(1, vless_adv_sign)

    if dnt_bool:
        raw_matches_tls.insert(2, vless_dnt_sign)
        raw_matches_non_tls.insert(2, vless_dnt_sign)
        raw_matches_tcp.insert(2, vless_dnt_sign)
        raw_matches_ws.insert(2, vless_dnt_sign)
        raw_matches_http.insert(2, vless_dnt_sign)
        raw_matches_grpc.insert(2, vless_dnt_sign)

    raw_matches_tls.append(vless_dev_sign)
    raw_matches_non_tls.append(vless_dev_sign)
    raw_matches_tcp.append(vless_dev_sign)
    raw_matches_ws.append(vless_dev_sign)
    raw_matches_http.append(vless_dev_sign)
    raw_matches_grpc.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./subscribe/security/tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_tls).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/security/non-tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_non_tls).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/networks/tcp", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_tcp).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/networks/ws", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_ws).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/networks/http", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_http).encode("utf-8")).decode("utf-8"))
    with open("./subscribe/networks/grpc", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(raw_matches_grpc).encode("utf-8")).decode("utf-8"))

    array_shadowsocks_channels.insert(0, shadowsocks_update)
    array_trojan_channels.insert(0, trojan_update)
    array_vmess_channels.insert(0, vmess_update)
    array_vless_channels.insert(0, vless_update)
    array_reality_channels.insert(0, reality_update)
    array_tuic_channels.insert(0, vless_update)
    array_hysteria_channels.insert(0, vless_update)
    array_juicity_channels.insert(0, vless_update)

    if adv_bool:
        array_shadowsocks_channels.insert(1, shadowsocks_adv_sign)
        array_trojan_channels.insert(1, trojan_adv_sign)
        array_vmess_channels.insert(1, vmess_adv_sign)
        array_vless_channels.insert(1, vless_adv_sign)
        array_reality_channels.insert(1, reality_adv_sign)
        array_tuic_channels.insert(1, vless_adv_sign)
        array_hysteria_channels.insert(1, vless_adv_sign)
        array_juicity_channels.insert(1, vless_adv_sign)

    if dnt_bool:
        array_shadowsocks_channels.insert(2, shadowsocks_dnt_sign)
        array_trojan_channels.insert(2, trojan_dnt_sign)
        array_vmess_channels.insert(2, vmess_dnt_sign)
        array_vless_channels.insert(2, vless_dnt_sign)
        array_reality_channels.insert(2, reality_dnt_sign)
        array_tuic_channels.insert(2, vless_dnt_sign)
        array_hysteria_channels.insert(2, vless_dnt_sign)
        array_juicity_channels.insert(2, vless_dnt_sign)

    array_shadowsocks_channels.append(shadowsocks_dev_sign)
    array_trojan_channels.append(trojan_dev_sign)
    array_vmess_channels.append(vmess_dev_sign)
    array_vless_channels.append(vless_dev_sign)
    array_reality_channels.append(reality_dev_sign)
    array_tuic_channels.append(vless_dev_sign)
    array_hysteria_channels.append(vless_dev_sign)
    array_juicity_channels.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./channels/protocols/shadowsocks", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_shadowsocks_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/trojan", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_trojan_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/vmess", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_vmess_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/vless", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_vless_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/reality", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_reality_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/tuic", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tuic_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/hysteria", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_hysteria_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/protocols/juicity", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_juicity_channels).encode("utf-8")).decode("utf-8"))


    array_tls_channels.insert(0, vless_update)
    array_non_tls_channels.insert(0, vless_update)
    array_tcp_channels.insert(0, vless_update)
    array_ws_channels.insert(0, vless_update)
    array_http_channels.insert(0, vless_update)
    array_grpc_channels.insert(0, vless_update)

    if adv_bool:
        array_tls_channels.insert(1, vless_adv_sign)
        array_non_tls_channels.insert(1, vless_adv_sign)
        array_tcp_channels.insert(1, vless_adv_sign)
        array_ws_channels.insert(1, vless_adv_sign)
        array_http_channels.insert(1, vless_adv_sign)
        array_grpc_channels.insert(1, vless_adv_sign)

    if dnt_bool:
        array_tls_channels.insert(2, vless_dnt_sign)
        array_non_tls_channels.insert(2, vless_dnt_sign)
        array_tcp_channels.insert(2, vless_dnt_sign)
        array_ws_channels.insert(2, vless_dnt_sign)
        array_http_channels.insert(2, vless_dnt_sign)
        array_grpc_channels.insert(2, vless_dnt_sign)

    array_tls_channels.append(vless_dev_sign)
    array_non_tls_channels.append(vless_dev_sign)
    array_tcp_channels.append(vless_dev_sign)
    array_ws_channels.append(vless_dev_sign)
    array_http_channels.append(vless_dev_sign)
    array_grpc_channels.append(vless_dev_sign)

    # Save configurations into files splitted based on configuration type
    with open("./channels/security/tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tls_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/security/non-tls", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_non_tls_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/networks/tcp", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_tcp_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/networks/ws", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_ws_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/networks/http", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_http_channels).encode("utf-8")).decode("utf-8"))
    with open("./channels/networks/grpc", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(array_grpc_channels).encode("utf-8")).decode("utf-8"))


    write_readme()
    atomic_write_text("telegram channels.json", json.dumps(telegram_channels, indent=4))
    atomic_write_text("invalid telegram channels.json", json.dumps(invalid_telegram_channels, indent=4))


def main():
    last_update_datetime = read_last_update()
    current_datetime_update = datetime.now(IRAN_TIMEZONE)
    print(f"Latest Update: {last_update_datetime.isoformat()}\nCurrent Update: {current_datetime_update.isoformat()}")
    collect_configs(last_update_datetime, current_datetime_update)
    # A failed run must not advance the watermark and cause messages to be skipped.
    atomic_write_text("last update", current_datetime_update.isoformat(sep=" ", timespec="microseconds"))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main()
