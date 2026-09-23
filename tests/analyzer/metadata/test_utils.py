import logging
import socket
from unittest.mock import Mock

import pytest
from whois import NICClient

from guarddog.analyzer.metadata.utils import get_domain_creation_date


@pytest.mark.parametrize(
    "level", [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]
)
def test_whois_socket_timeout_logging(monkeypatch, caplog, capsys, level):
    """Exercise the real WHOIS error handling without making network requests."""
    connection = Mock()
    connection.connect.side_effect = socket.timeout("timed out")
    monkeypatch.setattr(NICClient, "get_socket", lambda self: connection)
    monkeypatch.setattr(
        NICClient, "choose_server", lambda self, domain: "whois.example.com"
    )
    get_domain_creation_date.cache_clear()

    try:
        with caplog.at_level(level, logger="guarddog"):
            # A failed lookup must not imply that a maintainer domain is unregistered.
            assert get_domain_creation_date("example.com") == (None, True)

        assert ("Error trying to connect to socket" in caplog.text) == (
            level == logging.DEBUG
        )
        assert capsys.readouterr() == ("", "")
        connection.close.assert_called_once()
    finally:
        get_domain_creation_date.cache_clear()
