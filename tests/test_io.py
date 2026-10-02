from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from maxminddb import InvalidDatabaseError
import pytest
import requests

import collector_io


def response_for(monkeypatch, chunks=(b"new database",)):
    response = MagicMock()
    response.__enter__.return_value = response
    response.iter_content.return_value = iter(chunks)
    get = MagicMock(return_value=response)
    monkeypatch.setattr(collector_io.requests, "get", get)
    return response, get


def test_fetch_text_sets_timeout_and_checks_status(monkeypatch):
    response, get = response_for(monkeypatch)
    response.text = "subscription data"
    assert collector_io.fetch_text("https://example.org/feed") == "subscription data"
    get.assert_called_once_with("https://example.org/feed", timeout=collector_io.REQUEST_TIMEOUT)
    response.raise_for_status.assert_called_once_with()


def test_http_error_is_not_parsed_as_a_feed(monkeypatch):
    response, _ = response_for(monkeypatch)
    response.raise_for_status.side_effect = requests.HTTPError("503 Service Unavailable")
    with pytest.raises(requests.HTTPError):
        collector_io.fetch_text("https://example.org/feed")


def test_atomic_text_write_replaces_complete_contents(tmp_path):
    path = tmp_path / "last update"
    path.write_text("old")
    collector_io.atomic_write_text(path, "new 🌍")
    assert path.read_text() == "new 🌍"
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_write_failure_preserves_original_and_cleans_temporary(tmp_path, monkeypatch):
    path = tmp_path / "last update"
    path.write_text("old")

    def fail_replace(*args):
        raise OSError("disk error")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError):
        collector_io.atomic_write_text(path, "new")
    assert path.read_text() == "old"
    assert list(tmp_path.glob("*.tmp")) == []


def test_geoip_download_validates_before_replacing_existing_database(tmp_path, monkeypatch):
    path = tmp_path / "country.mmdb"
    path.write_bytes(b"old database")
    response, get = response_for(monkeypatch, (b"new ", b"", b"database"))

    def validate(temporary):
        assert temporary.read_bytes() == b"new database"
        assert path.read_bytes() == b"old database"

    monkeypatch.setattr(collector_io, "validate_geoip_database", validate)
    collector_io.download_geoip_database(path)
    assert path.read_bytes() == b"new database"
    get.assert_called_once_with(collector_io.GEOIP_URL, timeout=collector_io.REQUEST_TIMEOUT, stream=True)
    response.raise_for_status.assert_called_once()
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.parametrize("failure", ["http", "stream", "invalid"])
def test_failed_database_download_preserves_cached_file(tmp_path, monkeypatch, failure):
    path = tmp_path / "country.mmdb"
    path.write_bytes(b"old database")
    response, _ = response_for(monkeypatch, (b"not a database",))
    if failure == "http":
        response.raise_for_status.side_effect = requests.HTTPError("404")
    elif failure == "stream":

        def broken_stream(**kwargs):
            yield b"partial data"
            raise requests.Timeout("stream timed out")

        response.iter_content.side_effect = broken_stream
    # The real reader rejects the invalid streamed bytes in the third case.
    with pytest.raises((requests.RequestException, InvalidDatabaseError)):
        collector_io.download_geoip_database(path)
    assert path.read_bytes() == b"old database"
    assert list(tmp_path.glob("*.tmp")) == []


def test_geoip_refresh_uses_a_valid_cached_copy(tmp_path, monkeypatch, caplog):
    path = tmp_path / "country.mmdb"
    path.write_bytes(b"cached")

    def fail_download(*args):
        raise requests.Timeout("offline")

    validator = MagicMock()
    monkeypatch.setattr(collector_io, "download_geoip_database", fail_download)
    monkeypatch.setattr(collector_io, "validate_geoip_database", validator)
    assert collector_io.refresh_geoip_database(path) is False
    validator.assert_called_once_with(path)
    assert path.read_bytes() == b"cached"
    assert "using the cached database" in caplog.text


@pytest.mark.parametrize("exists", [False, True])
def test_geoip_refresh_cannot_use_a_missing_or_invalid_cache(tmp_path, monkeypatch, exists):
    path = tmp_path / "country.mmdb"
    if exists:
        path.write_bytes(b"not a database")

    def fail_download(*args):
        raise requests.Timeout("offline")

    monkeypatch.setattr(collector_io, "download_geoip_database", fail_download)
    with pytest.raises((OSError, InvalidDatabaseError)):
        collector_io.refresh_geoip_database(path)


@pytest.mark.parametrize("database_type,valid", [("GeoLite2-Country", True), ("GeoLite2-City", False)])
def test_geoip_database_type_is_checked(monkeypatch, database_type, valid):
    reader = MagicMock()
    reader.__enter__.return_value = reader
    reader.metadata.return_value = SimpleNamespace(database_type=database_type)
    monkeypatch.setattr(collector_io.geoip2.database, "Reader", MagicMock(return_value=reader))
    if valid:
        collector_io.validate_geoip_database("unused.mmdb")
    else:
        with pytest.raises(ValueError, match="country database"):
            collector_io.validate_geoip_database("unused.mmdb")
