import pytest
from aimenreco.core.scanner import Scanner

def test_scanner_noise_filtering_logic():
    """
    Test the core filtering logic of the Scanner.
    Verifies that DNA signatures, protocol upgrades, and manual filters 
    correctly identify 'noise' responses.
    """
    # Mock Wildcard DNA (has_w, hash, size, status, redir)
    w_data = (True, "d41d8cd98f00b204e9800998ecf8427e", 808, 404, None)
    
    class FakeLogger:
        quiet = True
        def info(self, m): pass
        def status(self, m): pass

    # Initialize scanner
    scanner = Scanner(
        url="http://example.com",
        threads=1,
        timeout=1,
        wildcard_data=w_data,
        logger=FakeLogger(),
        sf=1234 # Manual size filter
    )

    # CASE 1: Match by MD5 Hash (DNA)
    noise, _ = scanner.is_noise(200, 500, "d41d8cd98f00b204e9800998ecf8427e", "", "http://example.com/test")
    assert noise is True

    # CASE 2: Match by Status and Size tolerance (DNA)
    # 810 is within the 15-byte tolerance of 808
    noise, _ = scanner.is_noise(404, 810, "different_hash", "", "http://example.com/test")
    assert noise is True

    # CASE 3: Protocol Masking (Redirecting from http to https of the same URL)
    noise, n_type = scanner.is_noise(301, 0, "hash", "https://example.com/test", "http://example.com/test")
    assert noise is True
    assert n_type == "protocol"

    # CASE 4: Manual Size Filter
    noise, _ = scanner.is_noise(200, 1234, "hash", "", "http://example.com/test")
    assert noise is True

    # CASE 5: Valid Finding (No matches)
    noise, _ = scanner.is_noise(200, 5000, "new_hash", "", "http://example.com/real-page")
    assert noise is False