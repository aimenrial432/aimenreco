import pytest
from unittest.mock import MagicMock, patch
import json
from aimenreco.core.passive import PassiveScanner
from aimenreco.core.intel import TechAnalyzer

class FakeLogger:
    def __init__(self):
        self.messages = []
        self.quiet = False
    def info(self, msg): self.messages.append(msg)
    def warn(self, msg): self.messages.append(msg)
    def error(self, msg): self.messages.append(msg)
    def success(self, msg): self.messages.append(msg)
    def tree(self, label, value, color=None, is_last=False): 
        self.messages.append(f"{label}: {value}")

# --- Existing tests updated for compatibility ---

def test_passive_initialization_cleaning():
    """
    Test Case: Domain Normalization and Sanitary Checks.
    Validates that the PassiveScanner correctly isolates the FQDN.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("https://sub.target.com:443/api/v1?id=1", logger)
    assert scanner.domain == "sub.target.com"
    
    scanner_www = PassiveScanner("www.example.org/", logger)
    assert scanner_www.domain == "example.org"

# --- New Advanced Tests ---

def test_fallback_to_hackertarget_on_crt_failure():
    """
    Test Case: Failover Logic (crt.sh -> HackerTarget).
    
    Simulates a scenario where crt.sh fails all 4 retries (503 error)
    and verifies the scanner automatically attempts HackerTarget API
    to ensure discovery continuity.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mocking dependencies
    with patch.object(scanner, '_run_tech_phase', return_value=None), \
         patch.object(scanner, '_run_whois_phase', return_value=None), \
         patch("time.sleep", return_value=None):
        
        with patch("requests.get") as mock_get:
            # 4 failures for crt.sh, then 1 success for HackerTarget
            # HackerTarget returns plain text with "subdomain,ip" format
            mock_get.side_effect = [
                MagicMock(status_code=503), # crt.sh try 1
                MagicMock(status_code=503), # crt.sh try 2
                MagicMock(status_code=503), # crt.sh try 3
                MagicMock(status_code=503), # crt.sh try 4
                MagicMock(status_code=200, text="api.target.com,1.1.1.1\ndev.target.com,2.2.2.2") # HackerTarget
            ]
            
            results = scanner.fetch_subdomains()
            
            assert "api.target.com" in results
            assert "dev.target.com" in results
            assert mock_get.call_count == 5 # 4 (crt.sh) + 1 (HackerTarget)
            assert any("Trying HackerTarget" in m for m in logger.messages)

def test_tech_analyzer_whatweb_integration():
    """
    Test Case: WhatWeb Binary Execution and Parsing.
    
    Validates that TechAnalyzer correctly executes the whatweb command
    and parses the JSON output into the technology stack.
    """
    logger = FakeLogger()
    analyzer = TechAnalyzer(logger)
    
    # Mock subprocess.run to simulate whatweb output
    mock_stdout = json.dumps([{
        "plugins": {
            "Apache": {"version": ["2.4.41"]},
            "PHP": {"version": ["7.4.3"]},
            "Bootstrap": {}
        }
    }])
    
    with patch("shutil.which", return_value="/usr/bin/whatweb"), \
         patch("subprocess.run") as mock_run:
        
        mock_run.return_value = MagicMock(stdout=mock_stdout, returncode=0)
        
        results = analyzer.get_whatweb("http://target.com")
        
        assert "Apache (2.4.41)" in results
        assert "PHP (7.4.3)" in results
        assert "Bootstrap" in results

def test_tech_analyzer_favicon_hashing():
    """
    Test Case: Favicon MD5 Fingerprinting.
    
    Ensures that TechAnalyzer can fetch a favicon, calculate its MD5 hash,
    and match it against the internal signature database (favicons.json).
    """
    logger = FakeLogger()
    analyzer = TechAnalyzer(logger)
    
    # Set up a mock database
    analyzer.favicon_db = {"f0286392010e0172010e0172010e0172": "WordPress"}
    
    # Content that produces the MD5 above
    favicon_content = b"\x00" * 10 
    import hashlib
    mock_md5 = hashlib.md5(favicon_content).hexdigest()
    analyzer.favicon_db = {mock_md5: "WordPress"}

    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, content=favicon_content)
        
        results = analyzer.get_favicon_hash("http://target.com")
        
        assert "CMS: WordPress (via Favicon)" in results

def test_tech_analyzer_header_extraction():
    """
    Test Case: HTTP Header Fingerprinting.
    
    Checks if the analyzer correctly identifies software from 
    'Server' and 'X-Powered-By' headers.
    """
    logger = FakeLogger()
    analyzer = TechAnalyzer(logger)
    
    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            headers={
                "Server": "nginx/1.18.0",
                "X-Powered-By": "Express"
            }
        )
        
        results = analyzer.get_headers_tech("http://target.com")
        
        assert "Server: nginx/1.18.0" in results
        assert "Powered-By: Express" in results

def test_full_passive_tech_stack_aggregation():
    """
    Test Case: Technology Stack Aggregation Integrity.
    
    Verifies that the PassiveScanner correctly aggregates results from 
    all sub-modules (WhatWeb, Headers, Favicon) into a single sorted list.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mocking all analyzer methods to return specific values
    with patch("aimenreco.core.intel.TechAnalyzer.get_whatweb", return_value=["Apache"]), \
         patch("aimenreco.core.intel.TechAnalyzer.get_headers_tech", return_value=["PHP"]), \
         patch("aimenreco.core.intel.TechAnalyzer.get_favicon_hash", return_value=["CMS: WordPress"]):
        
        scanner._run_tech_phase()
        
        # Verify logger intercepted the tree calls
        assert "Technology: Apache" in logger.messages
        assert "Technology: PHP" in logger.messages
        assert "Technology: CMS: WordPress" in logger.messages