import pytest
from datetime import datetime
from typing import Any, Optional, Dict, List

# Core imports
from aimenreco.core.whois_module import WhoisAnalyzer
from aimenreco.utils.exceptions import UserAbortException

def test_whois_parsing_logic(mocker: Any, logger: Any) -> None:
    """
    Test Case: WHOIS Data Normalization.
    
    Verifies that the analyzer correctly handles inconsistent data types 
    returned by the whois library (lists vs strings).
    """
    # 1. Setup Mock Response
    mock_whois_data = mocker.Mock()
    mock_whois_data.domain_name = ["example.com"]
    mock_whois_data.registrar = ["NameCheap, Inc."]
    mock_whois_data.creation_date = [datetime(2020, 1, 1)]
    mock_whois_data.expiration_date = datetime(2026, 1, 1)
    mock_whois_data.name_servers = ["NS1.CLOUDFLARE.COM", "ns2.cloudflare.com"]
    mock_whois_data.emails = "admin@example.com"

    mocker.patch("whois.whois", return_value=mock_whois_data)

    analyzer = WhoisAnalyzer("example.com", logger)
    results: Optional[Dict[str, Any]] = analyzer.run()

    # 2. Assertions
    assert results is not None
    assert results["registrar"] == "NameCheap, Inc."
    assert results["tech_info"] == "Cloudflare WAF Detected"

def test_whois_empty_response(mocker: Any, logger: Any) -> None:
    """
    Test Case: Handling Missing Domain Data.
    """
    mock_empty = mocker.Mock()
    mock_empty.domain_name = None 
    mocker.patch("whois.whois", return_value=mock_empty)
    mocker.patch("time.sleep", return_value=None)

    analyzer = WhoisAnalyzer("nonexistent.test", logger)
    results = analyzer.run()

    assert results is None

def test_whois_connection_retry_and_fail(mocker: Any, logger: Any) -> None:
    """
    Test Case: Resilience and Retry Logic.
    """
    mock_query = mocker.patch("whois.whois", side_effect=Exception("Connection reset"))
    mocker.patch("time.sleep", return_value=None)

    analyzer = WhoisAnalyzer("fail.com", logger)
    results = analyzer.run()

    assert mock_query.call_count == 3
    assert results is None

def test_whois_keyboard_interrupt(mocker: Any, logger: Any) -> None:
    """
    Test Case: User Abort (SIGINT).
    """
    mocker.patch("whois.whois", side_effect=KeyboardInterrupt)
    analyzer = WhoisAnalyzer("interrupt.com", logger)
    
    with pytest.raises(UserAbortException):
        analyzer.run()