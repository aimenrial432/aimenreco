import pytest
import json
import hashlib
from typing import Any, List, Set, cast
from aimenreco.core.passive import PassiveScanner
from aimenreco.core.intel import TechAnalyzer

# --- Passive Discovery Tests ---

def test_passive_initialization_cleaning(logger: Any) -> None:
    """
    Test Case: Domain Normalization and Sanitization.
    
    Validates that the PassiveScanner correctly isolates the FQDN 
    from complex URLs, stripping protocols, ports, and paths.
    """
    scanner = PassiveScanner("https://sub.target.com:443/api/v1?id=1", logger)
    assert scanner.domain == "sub.target.com"
    
    scanner_www = PassiveScanner("www.example.org/", logger)
    assert scanner_www.domain == "example.org"

def test_fallback_to_hackertarget_on_crt_failure(mocker: Any, logger: Any) -> None:
    """
    Test Case: Failover Logic (crt.sh -> HackerTarget).
    
    Simulates a scenario where crt.sh fails all retries (503 error)
    and verifies the scanner automatically attempts the HackerTarget API.
    """
    scanner = PassiveScanner("target.com", logger)
    
    # Mock internal phases and sleep to speed up execution
    mocker.patch.object(scanner, '_run_tech_phase', return_value=None)
    mocker.patch.object(scanner, '_run_whois_phase', return_value=None)
    mocker.patch("time.sleep", return_value=None)
    
    # Simulate 4 failures for crt.sh, then 1 success for HackerTarget
    mock_get = mocker.patch("requests.get")
    mock_get.side_effect = [
        mocker.Mock(status_code=503), # crt.sh try 1
        mocker.Mock(status_code=503), # crt.sh try 2
        mocker.Mock(status_code=503), # crt.sh try 3
        mocker.Mock(status_code=503), # crt.sh try 4
        mocker.Mock(
            status_code=200, 
            text="api.target.com,1.1.1.1\ndev.target.com,2.2.2.2"
        ) # HackerTarget response
    ]
    
    # FIX: Wrap the result in set() to satisfy the linter
    # This ensures 'results' is explicitly a Set[str]
    results: Set[str] = set(scanner.fetch_subdomains())
    
    assert "api.target.com" in results
    assert "dev.target.com" in results
    assert mock_get.call_count == 5
    
    # Verify fallback log message was triggered
    assert any("Trying HackerTarget" in m for m in logger.messages)

# --- Intelligence & Tech Analysis Tests ---

def test_tech_analyzer_whatweb_integration(mocker: Any, logger: Any) -> None:
    """
    Test Case: WhatWeb Binary Execution and Output Parsing.
    """
    analyzer = TechAnalyzer(logger)
    
    mock_stdout: str = json.dumps([{
        "plugins": {
            "Apache": {"version": ["2.4.41"]},
            "PHP": {"version": ["7.4.3"]},
            "Bootstrap": {}
        }
    }])
    
    mocker.patch("shutil.which", return_value="/usr/bin/whatweb")
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = mocker.Mock(stdout=mock_stdout, returncode=0)
    
    results: List[str] = analyzer.get_whatweb("http://target.com")
    
    assert "Apache (2.4.41)" in results
    assert "PHP (7.4.3)" in results
    assert "Bootstrap" in results

def test_tech_analyzer_favicon_hashing(mocker: Any, logger: Any) -> None:
    """
    Test Case: Favicon MD5 Fingerprinting.
    """
    analyzer = TechAnalyzer(logger)
    favicon_content: bytes = b"fake-icon-data" 
    expected_hash: str = hashlib.md5(favicon_content).hexdigest()
    
    analyzer.favicon_db = {expected_hash: "WordPress"}

    mock_get = mocker.patch("requests.get")
    mock_get.return_value = mocker.Mock(status_code=200, content=favicon_content)
    
    results: List[str] = analyzer.get_favicon_hash("http://target.com")
    
    assert "CMS: WordPress (via Favicon)" in results

def test_tech_analyzer_header_extraction(mocker: Any, logger: Any) -> None:
    """
    Test Case: HTTP Header Fingerprinting.
    """
    analyzer = TechAnalyzer(logger)
    
    mock_get = mocker.patch("requests.get")
    mock_get.return_value = mocker.Mock(
        headers={
            "Server": "nginx/1.18.0",
            "X-Powered-By": "Express"
        }
    )
    
    results: List[str] = analyzer.get_headers_tech("http://target.com")
    
    assert "Server: nginx/1.18.0" in results
    assert "Powered-By: Express" in results

def test_full_passive_tech_stack_aggregation(mocker: Any, logger: Any) -> None:
    """
    Test Case: Technology Stack Aggregation Integrity.
    """
    scanner = PassiveScanner("target.com", logger)
    
    mocker.patch("aimenreco.core.intel.TechAnalyzer.get_whatweb", return_value=["Apache"])
    mocker.patch("aimenreco.core.intel.TechAnalyzer.get_headers_tech", return_value=["PHP"])
    mocker.patch("aimenreco.core.intel.TechAnalyzer.get_favicon_hash", return_value=["CMS: WordPress"])
    
    scanner._run_tech_phase()
    
    assert any("Technology: Apache" in m for m in logger.messages)
    assert any("Technology: PHP" in m for m in logger.messages)
    assert any("Technology: CMS: WordPress" in m for m in logger.messages)