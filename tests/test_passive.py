import pytest
from unittest.mock import MagicMock, patch
import json
import hashlib
from aimenreco.core.passive import PassiveScanner
from aimenreco.core.intel import TechAnalyzer

class FakeLogger:
    """
    Mock logger to intercept and validate output during testing.
    """
    def __init__(self):
        self.messages = []
        self.quiet = False

    def info(self, msg, color=None): self.messages.append(msg)
    def warn(self, msg, color=None): self.messages.append(msg)
    def error(self, msg, color=None): self.messages.append(msg)
    def success(self, msg, color=None): self.messages.append(msg)
    def process(self, msg, color=None): self.messages.append(msg) # Fixed: Added to resolve AttributeError
    def tree(self, label, value, color=None, is_last=False): 
        self.messages.append(f"{label}: {value}")

# --- Passive Discovery Tests ---

def test_passive_initialization_cleaning():
    """
    Test Case: Domain Normalization and Sanitization.
    Validates that the PassiveScanner correctly isolates the FQDN from complex URLs.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("https://sub.target.com:443/api/v1?id=1", logger)
    assert scanner.domain == "sub.target.com"
    
    scanner_www = PassiveScanner("www.example.org/", logger)
    assert scanner_www.domain == "example.org"

def test_fallback_to_hackertarget_on_crt_failure():
    """
    Test Case: Failover Logic (crt.sh -> HackerTarget).
    
    Simulates a scenario where crt.sh fails all 4 retries (e.g., 503 error)
    and verifies the scanner automatically attempts the HackerTarget API
    to ensure discovery continuity.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mocking internal phases and sleep to speed up the test
    with patch.object(scanner, '_run_tech_phase', return_value=None), \
         patch.object(scanner, '_run_whois_phase', return_value=None), \
         patch("time.sleep", return_value=None):
        
        with patch("requests.get") as mock_get:
            # Simulate 4 failures for crt.sh, then 1 success for HackerTarget
            mock_get.side_effect = [
                MagicMock(status_code=503), # crt.sh try 1
                MagicMock(status_code=503), # crt.sh try 2
                MagicMock(status_code=503), # crt.sh try 3
                MagicMock(status_code=503), # crt.sh try 4
                MagicMock(status_code=200, text="api.target.com,1.1.1.1\ndev.target.com,2.2.2.2") # HackerTarget response
            ]
            
            results = scanner.fetch_subdomains()
            
            assert "api.target.com" in results
            assert "dev.target.com" in results
            assert mock_get.call_count == 5  # 4 (crt.sh) + 1 (HackerTarget)
            # Verify the fallback warning was logged
            assert any("Trying HackerTarget" in m for m in logger.messages)

# --- Intelligence & Tech Analysis Tests ---

def test_tech_analyzer_whatweb_integration():
    """
    Test Case: WhatWeb Binary Execution and Output Parsing.
    
    Validates that TechAnalyzer correctly executes the whatweb command
    and parses the JSON response into the technology stack list.
    """
    logger = FakeLogger()
    analyzer = TechAnalyzer(logger)
    
    # Mock JSON output from whatweb
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
    
    Ensures that TechAnalyzer can fetch a remote favicon, calculate its MD5 hash,
    and match it against the internal signature database.
    """
    logger = FakeLogger()
    analyzer = TechAnalyzer(logger)
    
    # Create content and its corresponding MD5 hash
    favicon_content = b"fake-icon-data" 
    expected_hash = hashlib.md5(favicon_content).hexdigest()
    
    # Set up the mock database with the expected hash
    analyzer.favicon_db = {expected_hash: "WordPress"}

    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, content=favicon_content)
        
        results = analyzer.get_favicon_hash("http://target.com")
        
        assert "CMS: WordPress (via Favicon)" in results

def test_tech_analyzer_header_extraction():
    """
    Test Case: HTTP Header Fingerprinting.
    
    Checks if the analyzer correctly identifies software versions and 
    technologies from 'Server' and 'X-Powered-By' HTTP response headers.
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
    
    Verifies that the PassiveScanner correctly aggregates and displays results 
    from all technical sub-modules (WhatWeb, Headers, Favicon) via the logger.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mocking all analyzer methods to return specific mock data
    with patch("aimenreco.core.intel.TechAnalyzer.get_whatweb", return_value=["Apache"]), \
         patch("aimenreco.core.intel.TechAnalyzer.get_headers_tech", return_value=["PHP"]), \
         patch("aimenreco.core.intel.TechAnalyzer.get_favicon_hash", return_value=["CMS: WordPress"]):
        
        scanner._run_tech_phase()
        
        # Verify logger intercepted the tree-formatted calls
        assert "Technology: Apache" in logger.messages
        assert "Technology: PHP" in logger.messages
        assert "Technology: CMS: WordPress" in logger.messages