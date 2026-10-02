"""Bounded HTTP requests and atomic writes for collection metadata/databases."""

import logging
from pathlib import Path
import tempfile

import geoip2.database
from maxminddb import InvalidDatabaseError
import requests


LOGGER = logging.getLogger(__name__)
REQUEST_TIMEOUT = (5, 20)
GEOIP_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEOIP_PATH = Path("geoip-lite/geoip-lite-country.mmdb")


def fetch_text(url):
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.text


def atomic_write_text(path, content):
    """Replace a text file only after its complete contents have been written."""
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def validate_geoip_database(path):
    with geoip2.database.Reader(str(path)) as reader:
        if "Country" not in reader.metadata().database_type:
            raise ValueError("Expected a GeoIP country database")


def download_geoip_database(path=GEOIP_PATH, url=GEOIP_URL):
    """Stream and validate a new database before replacing a usable local copy."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with requests.get(url, timeout=REQUEST_TIMEOUT, stream=True) as response:
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        temporary.write(chunk)
        validate_geoip_database(temporary_path)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def refresh_geoip_database(path=GEOIP_PATH):
    """Use a validated cached copy on a transient download failure, if available."""
    path = Path(path)
    try:
        download_geoip_database(path)
    except (requests.RequestException, OSError, ValueError, InvalidDatabaseError) as exc:
        # Invalid/missing caches are fatal; do not proceed with a corrupt database.
        validate_geoip_database(path)
        LOGGER.warning("GeoIP refresh failed; using the cached database: %s", exc)
        return False
    return True
