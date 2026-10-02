# Telegram Configs Collector

## Introduction
The script systematically collects Vmess, Vless, ShadowSocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from publicly accessible Telegram channels. It categorizes these configurations based on open and closed ports, eliminates duplicate entries, resolves configuration addresses using IP addresses, and revises configuration titles to reflect server and protocol-type properties. These properties include network and security type, IP address and port, and the respective country associated with the configuration.

![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/0xjavid/telegram-configs-collector?label=Last%20Commit&color=%2338914b)
![GitHub](https://img.shields.io/github/license/0xjavid/telegram-configs-collector?label=License&color=yellow)
![GitHub Repo stars](https://img.shields.io/github/stars/0xjavid/telegram-configs-collector?label=Stars&color=red&style=flat)
![GitHub forks](https://img.shields.io/github/forks/0xjavid/telegram-configs-collector?label=Forks&color=blue&style=flat)
[![Execute On Schedule](https://github.com/0xjavid/telegram-configs-collector/actions/workflows/schedule.yml/badge.svg)](https://github.com/0xjavid/telegram-configs-collector/actions/workflows/schedule.yml)
[![Execute On Push](https://github.com/0xjavid/telegram-configs-collector/actions/workflows/push.yml/badge.svg)](https://github.com/0xjavid/telegram-configs-collector/actions/workflows/push.yml)

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
| **Juicity Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/juicity) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/juicity) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/juicity) |
| **Hysteria Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/hysteria) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/hysteria) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/hysteria) |
| **Tuic Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/tuic) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/tuic) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/tuic) |
| **Reality Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/reality) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/reality) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/reality) |
| **Vless Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/vless) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/vless) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/vless) |
| **Vmess Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/vmess) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/vmess) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/vmess) |
| **Trojan Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/trojan) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/trojan) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/trojan) |
| **Shadowsocks Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/protocols/shadowsocks) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/protocols/shadowsocks) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/protocols/shadowsocks) |
| **Mixed Type Configurations** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/splitted/mixed) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/splitted/channels) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/splitted/subscribe) |

## Network Type Subscription Links
Subscription links for configurations are organized according to network type and categorized into separate Telegram channels and subscription links. These links facilitate access to configurations optimized for specific network architectures.
| **Network Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Google Remote Procedure Call (GRPC)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/networks/grpc) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/networks/grpc) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/networks/grpc) |
| **Hypertext Transfer Protocol (HTTP)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/networks/http) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/networks/http) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/networks/http) |
| **WebSocket Protocol (WS)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/networks/ws) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/networks/ws) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/networks/ws) |
 | **Transmission Control Protocol (TCP)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/networks/tcp) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/networks/tcp) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/networks/tcp) |

## Security Type Subscription Links
Subscription links for configurations are organized according to security type and categorized into separate Telegram channels and subscription links. These links provide access to configurations with specific security implementations.
| **Security Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Transport Layer Security (TLS)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/security/tls) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/security/tls) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/security/tls) |
| **Non Transport Layer Security (Non-TLS)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/security/non-tls) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/security/non-tls) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/security/non-tls) |

## Internet Protocol Type Subscription Links
Subscription links for configurations are organized according to internet protocol type and categorized into separate Telegram channels and subscription links. These links enable access to configurations designed for specific internet protocol versions.
| **Internet Protocol Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:---:|:---:|:---:|:---:|
| **Internet Protocol Version 4 (IPV4)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/layers/ipv4) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/layers/ipv4) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/layers/ipv4) |
| **Internet Protocol Version 6 (IPV6)** | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/layers/ipv6) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/channels/layers/ipv6) | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/subscribe/layers/ipv6) |

## Country Subscription Links
Subscription links for configurations are organized according to country and provide access to specialized configurations for services that implement location-based restrictions. These configurations are particularly relevant for social media and artificial intelligence services that may restrict access or ban accounts when location changes are detected.
| **Code** | **Country Name** | **Subscription Link** | **Code** | **Country Name** | **Subscription Link** |
|:---:|:---:|:---:|:---:|:---:|:---:|
| AL | Albania | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/al/mixed) | AQ | Antarctica | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/aq/mixed) |
| AR | Argentina | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ar/mixed) | AM | Armenia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/am/mixed) |
| AU | Australia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/au/mixed) | AT | Austria | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/at/mixed) |
| AZ | Azerbaijan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/az/mixed) | BH | Bahrain | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/bh/mixed) |
| BE | Belgium | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/be/mixed) | BZ | Belize | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/bz/mixed) |
| BO | Bolivia, Plurinational State of | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/bo/mixed) | BA | Bosnia and Herzegovina | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ba/mixed) |
| BR | Brazil | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/br/mixed) | BG | Bulgaria | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/bg/mixed) |
| CA | Canada | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ca/mixed) | CL | Chile | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/cl/mixed) |
| CN | China | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/cn/mixed) | CO | Colombia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/co/mixed) |
| CR | Costa Rica | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/cr/mixed) | HR | Croatia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/hr/mixed) |
| CY | Cyprus | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/cy/mixed) | CZ | Czechia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/cz/mixed) |
| DK | Denmark | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/dk/mixed) | EC | Ecuador | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ec/mixed) |
| EG | Egypt | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/eg/mixed) | EE | Estonia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ee/mixed) |
| FI | Finland | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/fi/mixed) | FR | France | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/fr/mixed) |
| GE | Georgia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ge/mixed) | DE | Germany | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/de/mixed) |
| GI | Gibraltar | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/gi/mixed) | GR | Greece | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/gr/mixed) |
| GT | Guatemala | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/gt/mixed) | HK | Hong Kong | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/hk/mixed) |
| HU | Hungary | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/hu/mixed) | IS | Iceland | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/is/mixed) |
| IN | India | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/in/mixed) | ID | Indonesia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/id/mixed) |
| IR | Iran, Islamic Republic of | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ir/mixed) | IQ | Iraq | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/iq/mixed) |
| IE | Ireland | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ie/mixed) | IL | Israel | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/il/mixed) |
| IT | Italy | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/it/mixed) | JP | Japan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/jp/mixed) |
| JO | Jordan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/jo/mixed) | KZ | Kazakhstan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/kz/mixed) |
| KR | Korea, Republic of | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/kr/mixed) | KG | Kyrgyzstan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/kg/mixed) |
| LV | Latvia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/lv/mixed) | LT | Lithuania | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/lt/mixed) |
| LU | Luxembourg | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/lu/mixed) | MY | Malaysia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/my/mixed) |
| MT | Malta | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mt/mixed) | MH | Marshall Islands | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mh/mixed) |
| MU | Mauritius | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mu/mixed) | MX | Mexico | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mx/mixed) |
| MD | Moldova, Republic of | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/md/mixed) | MA | Morocco | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ma/mixed) |
| MM | Myanmar | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mm/mixed) | NP | Nepal | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/np/mixed) |
| NL | Netherlands | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/nl/mixed) | NZ | New Zealand | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/nz/mixed) |
| NG | Nigeria | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ng/mixed) | MK | North Macedonia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/mk/mixed) |
| NO | Norway | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/no/mixed) | NA | Not Available | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/na/mixed) |
| OM | Oman | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/om/mixed) | PK | Pakistan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/pk/mixed) |
| PY | Paraguay | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/py/mixed) | PE | Peru | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/pe/mixed) |
| PH | Philippines | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ph/mixed) | PL | Poland | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/pl/mixed) |
| PT | Portugal | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/pt/mixed) | PR | Puerto Rico | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/pr/mixed) |
| RO | Romania | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ro/mixed) | RU | Russian Federation | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ru/mixed) |
| SA | Saudi Arabia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/sa/mixed) | RS | Serbia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/rs/mixed) |
| SC | Seychelles | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/sc/mixed) | SG | Singapore | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/sg/mixed) |
| SK | Slovakia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/sk/mixed) | SI | Slovenia | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/si/mixed) |
| ZA | South Africa | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/za/mixed) | ES | Spain | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/es/mixed) |
| SE | Sweden | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/se/mixed) | CH | Switzerland | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ch/mixed) |
| TW | Taiwan, Province of China | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/tw/mixed) | TH | Thailand | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/th/mixed) |
| TR | Türkiye | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/tr/mixed) | UA | Ukraine | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ua/mixed) |
| AE | United Arab Emirates | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/ae/mixed) | GB | United Kingdom | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/gb/mixed) |
| US | United States | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/us/mixed) | UZ | Uzbekistan | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/uz/mixed) |
| VN | Viet Nam | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/vn/mixed) | VG | Virgin Islands, British | [Subscription Link](https://raw.githubusercontent.com/0xjavid/telegram-configs-collector/main/countries/vg/mixed) |

## Stats
[![Stars](https://starchart.cc/0xjavid/telegram-configs-collector.svg?variant=adaptive)](https://starchart.cc/0xjavid/telegram-configs-collector)

## Attribution
Based on [Soroush Mirzaei’s original project](https://github.com/soroushmirzaei/telegram-configs-collector), licensed under the [MIT License](license).
