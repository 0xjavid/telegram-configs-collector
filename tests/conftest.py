"""Synthetic data and strict network isolation for every test."""

import socket

from dns import resolver
import pytest
import requests

from config_utils import encode_vmess


TEST_UUID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def offline_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must not make HTTP, DNS, or socket requests")

    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(resolver.Resolver, "resolve", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.fixture
def output_directories():
    import main

    main.prepare_output_directories()


@pytest.fixture
def vmess():
    def make(**overrides):
        parameters = {
            "add": "192.0.2.1",
            "port": "443",
            "id": TEST_UUID,
            "ps": "Original title",
            "net": "tcp",
            "tls": "",
            "aid": "0",
        }
        parameters.update(overrides)
        return encode_vmess(parameters)

    return make
