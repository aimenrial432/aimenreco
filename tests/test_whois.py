import pytest
from datetime import datetime
# Import the custom exception to validate it in tests
from aimenreco.core.whois_module import WhoisAnalyzer
from aimenreco.utils.exceptions import UserAbortException

class FakeLogger:
    """Mock logger to capture output during WHOIS testing."""
    quiet = True
    def info(self, m): pass
    def error(self, m): pass
    def warn(self, m): pass

def test_whois_parsing_logic(mocker):
    """
    Test Case: WHOIS Data Normalization.
    Verifies that the analyzer correctly handles inconsistent data types 
    (lists vs strings) for dates, registrars, and nameservers.
    """
    # 1. Setup Mock Response
    mock_whois_data = mocker.Mock()
    # Library often returns lists for these fields
    mock_whois_data.domain_name = ["example.com", "EXAMPLE.COM"]
    mock_whois_data.registrar = ["NameCheap, Inc.", "Redundant Registrar"]
    mock_whois_data.org = "Example Corp"
    mock_whois_data.creation_date = [datetime(2020, 1, 1), datetime(2020, 1, 2)]
    mock_whois_data.expiration_date = datetime(2026, 1, 1)
    mock_whois_data.name_servers = ["NS1.CLOUDFLARE.COM", "ns2.cloudflare.com"]
    mock_whois_data.emails = "admin@example.com"

    # Patch the 'whois.whois' function
    mocker.patch("whois.whois", return_value=mock_whois_data)

    analyzer = WhoisAnalyzer("example.com", FakeLogger())
    results = analyzer.run()

    # 2. Assertions
    assert results is not None
    assert results["registrar"] == "NameCheap, Inc."
    assert results["creation_date"] == "2020-01-01"
    assert results["expiration_date"] == "2026-01-01"
    assert "ns1.cloudflare.com" in results["name_servers"]
    assert "admin@example.com" in results["emails"]
    assert results["tech_info"] == "Cloudflare WAF Detected"

def test_whois_empty_response(mocker):
    """
    Test Case: Handling Missing Domain Data.
    Ensures the analyzer returns None gracefully if the WHOIS server 
    returns an empty or invalid object.
    """
    mock_empty = mocker.Mock()
    mock_empty.domain_name = None 
    mocker.patch("whois.whois", return_value=mock_empty)
    # Patch sleep to avoid waiting during retries in tests
    mocker.patch("time.sleep", return_value=None)

    analyzer = WhoisAnalyzer("nonexistent.test", FakeLogger())
    results = analyzer.run()

    assert results is None

def test_whois_connection_retry_and_fail(mocker):
    """
    Test Case: Resilience and Retry Logic.
    Verifies that the tool attempts retries on failure and finally
    returns None after max retries are exhausted.
    """
    # Simulate a persistent exception
    mock_query = mocker.patch("whois.whois", side_effect=Exception("Connection reset"))
    mocker.patch("time.sleep", return_value=None)

    analyzer = WhoisAnalyzer("fail.com", FakeLogger())
    results = analyzer.run()

    # Verify it tried 3 times (max_retries)
    assert mock_query.call_count == 3
    assert results is None

def test_whois_keyboard_interrupt(mocker):
    """
    Test Case: User Abort (Ctrl+C).
    Verifies that a KeyboardInterrupt inside the WHOIS module is 
    translated into a UserAbortException for the global orchestrator.
    """
    # Simulate KeyboardInterrupt on the first call
    mocker.patch("whois.whois", side_effect=KeyboardInterrupt)
    
    analyzer = WhoisAnalyzer("interrupt.com", FakeLogger())
    
    # Now we expect UserAbortException, because that's what we raise 
    # in whois_module.py when a KeyboardInterrupt is caught.
    with pytest.raises(UserAbortException):
        analyzer.run()