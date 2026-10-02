# Telegram Configs Collector

## Introduction
The script systematically collects Vmess, Vless, ShadowSocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from publicly accessible Telegram channels. It categorizes these configurations based on open and closed ports, eliminates duplicate entries, resolves configuration addresses using IP addresses, and revises configuration titles to reflect server and protocol-type properties. These properties include network and security type, IP address and port, and the respective country associated with the configuration.

![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/{{repository}}?label=Last%20Commit&color=%2338914b)
![GitHub](https://img.shields.io/github/license/{{repository}}?label=License&color=yellow)
![GitHub Repo stars](https://img.shields.io/github/stars/{{repository}}?label=Stars&color=red&style=flat)
![GitHub forks](https://img.shields.io/github/forks/{{repository}}?label=Forks&color=blue&style=flat)
[![Execute On Schedule](https://github.com/{{repository}}/actions/workflows/schedule.yml/badge.svg)](https://github.com/{{repository}}/actions/workflows/schedule.yml)
[![Execute On Push](https://github.com/{{repository}}/actions/workflows/push.yml/badge.svg)](https://github.com/{{repository}}/actions/workflows/push.yml)

## Running the Collector
Use Python **3.11–3.14** (Python 3.14 is used by the collection workflows). From the repository root:

```sh
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip setuptools
python -m pip install -r requirements.txt
python main.py
```

The original `python -m pip install -r requirements` command is still supported.

- Configure sources in `telegram channels.json` and `subscription links.json`. The supplemental channel list from the original maintainer is optional.
- Running `main.py` contacts public sources, resolves hosts, checks TCP ports, and replaces generated subscription files. UDP protocols are not validated by a TCP port check.
- HTTP and DNS requests have timeouts. GeoIP downloads are validated and replaced atomically; a valid cached database is used if a refresh fails.
- `last update` is a timezone-aware checkpoint and only advances after a successful run. Runs with no usable configurations fail instead of publishing empty/header-only feeds.
- Importing `main` or `title` does not run the collector. Parsing, README rendering, and the test suite can be used offline.

**Public proxies are untrusted.** An open port does not prove a proxy works, is fast, or is safe. Avoid sending sensitive information through unknown endpoints.

### Fork-specific Links
Generated README/subscription links use this repository by default. GitHub Actions supplies `GITHUB_REPOSITORY` automatically; `SUBSCRIPTION_BRANCH` selects the branch used in raw-file URLs (default: `main`). To generate links for another fork locally:

```sh
GITHUB_REPOSITORY=owner/repository SUBSCRIPTION_BRANCH=main python main.py
```

## Development
Install the development dependencies and run the checks:

```sh
python -m pip install --upgrade pip setuptools
python -m pip install -r requirements-dev.txt
python -m pip check
python -m ruff check .
python -m pytest
```

Tests use synthetic configurations, temporary output directories, and mocked HTTP/DNS/socket operations. They do not refresh tracked feeds or contact Telegram/proxy servers. CI runs them on Python 3.11, 3.12, 3.13, and 3.14.

`readme.md` is generated from `docs/readme-template.md` and the country directories. Edit the template to keep documentation changes across collection runs. Regenerate **only the README**, without network access:

```sh
python -c "from main import write_readme; write_readme()"
```

## Automation
- **Python application:** dependency checks, lint, and offline tests on pushes and pull requests.
- **Execute On Push / Execute On Schedule:** a shared collection workflow on relevant `main` pushes, hourly at minute 15 (UTC), or manually through **Actions → Run workflow**. Manual runs publish to the selected branch.
- **Execute Code Scanning:** current CodeQL Python analysis on `main`, pull requests, and a weekly schedule.
- **Dependabot:** monthly Python dependency and pinned GitHub Action updates.

Publishing uses the built-in `GITHUB_TOKEN` with `contents: write`; no custom personal-access-token secret is needed. Only generated files are staged, collection runs are serialized per branch, and normal pushes preserve Git history. A protected branch or concurrent external edit can reject a push; the workflow will fail safely rather than force-push. Enable Actions/scheduled workflows in fork settings if GitHub has disabled them.

## Tutorial
This is a guide for configuring domains by routing type in the `nekoray` and `nekobox` applications when using the `sing-box` core. To implement these domain settings, create new routes in either application and add the appropriate domains to the relevant `domains` section. Configure the outbound setting as `bypass`, `proxy`, or `block` according to the specifications provided for each domain category.

- Bypass
```
geosite:category-ir
geosite:category-bank-ir
geosite:category-bourse-ir
geosite:category-education-ir
geosite:category-forums-ir
geosite:category-gov-ir
geosite:category-insurance-ir
geosite:category-media-ir
geosite:category-news-ir
geosite:category-payment-ir
geosite:category-scholar-ir
geosite:category-shopping-ir
geosite:category-social-media-ir
geosite:category-tech-ir
geosite:category-travel-ir
```

- Proxy
```
geosite:apple
geosite:adobe
geosite:anthropic
geosite:openai
geosite:clubhouse
geosite:netflix
geosite:nvidia
geosite:intel
geosite:amd
geosite:signal
geosite:soundcloud
geosite:youtube
geosite:telegram
geosite:twitter
geosite:instagram
geosite:facebook
geosite:pinterest
geosite:tiktok
geosite:spotify
geosite:twitch
geosite:discord
```

- Block
```
geosite:category-ads-all
geosite:category-ads-ir
geosite:google-ads
geosite:spotify-ads
geosite:adobe-ads
geosite:apple-ads
```

## Protocol Type Subscription Links
Subscription links for configurations are organized according to protocol type and categorized into separate Telegram channels and subscription links. These links provide access to configurations based on specific protocol requirements.
| **Protocol Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Juicity Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/juicity) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/juicity) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/juicity) |
| **Hysteria Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/hysteria) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/hysteria) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/hysteria) |
| **Tuic Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/tuic) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/tuic) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/tuic) |
| **Reality Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/reality) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/reality) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/reality) |
| **Vless Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/vless) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/vless) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/vless) |
| **Vmess Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/vmess) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/vmess) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/vmess) |
| **Trojan Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/trojan) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/trojan) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/trojan) |
| **Shadowsocks Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/protocols/shadowsocks) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/protocols/shadowsocks) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/protocols/shadowsocks) |
| **Mixed Type Configurations** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/splitted/mixed) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/splitted/channels) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/splitted/subscribe) |

## Network Type Subscription Links
Subscription links for configurations are organized according to network type and categorized into separate Telegram channels and subscription links. These links facilitate access to configurations optimized for specific network architectures.
| **Network Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Google Remote Procedure Call (GRPC)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/networks/grpc) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/networks/grpc) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/networks/grpc) |
| **Hypertext Transfer Protocol (HTTP)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/networks/http) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/networks/http) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/networks/http) |
| **WebSocket Protocol (WS)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/networks/ws) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/networks/ws) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/networks/ws) |
 | **Transmission Control Protocol (TCP)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/networks/tcp) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/networks/tcp) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/networks/tcp) |

## Security Type Subscription Links
Subscription links for configurations are organized according to security type and categorized into separate Telegram channels and subscription links. These links provide access to configurations with specific security implementations.
| **Security Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Transport Layer Security (TLS)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/security/tls) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/security/tls) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/security/tls) |
| **Non Transport Layer Security (Non-TLS)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/security/non-tls) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/security/non-tls) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/security/non-tls) |

## Internet Protocol Type Subscription Links
Subscription links for configurations are organized according to internet protocol type and categorized into separate Telegram channels and subscription links. These links enable access to configurations designed for specific internet protocol versions.
| **Internet Protocol Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Internet Protocol Version 4 (IPV4)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/layers/ipv4) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/layers/ipv4) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/layers/ipv4) |
| **Internet Protocol Version 6 (IPV6)** | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/layers/ipv6) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/channels/layers/ipv6) | [Subscription Link](https://raw.githubusercontent.com/{{repository}}/{{branch}}/subscribe/layers/ipv6) |

## Country Subscription Links
Subscription links for configurations are organized according to country and provide access to specialized configurations for services that implement location-based restrictions. These configurations are particularly relevant for social media and artificial intelligence services that may restrict access or ban accounts when location changes are detected.
{{country_table}}

## Stats
[![Stars](https://starchart.cc/{{repository}}.svg?variant=adaptive)](https://starchart.cc/{{repository}})

## Attribution
Based on [Soroush Mirzaei’s original project](https://github.com/soroushmirzaei/telegram-configs-collector), licensed under the [MIT License](license).
