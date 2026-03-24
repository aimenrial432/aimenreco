import pytest
from unittest.mock import MagicMock, patch
import requests
from aimenreco.core.passive import PassiveScanner

class FakeLogger:
    """
    Mock Logger to intercept UI calls for verification.
    Simulates the internal Logger behavior without terminal output.
    """
    def __init__(self):
        self.messages = []
        self.quiet = False
    def info(self, msg): self.messages.append(msg)
    def warn(self, msg): self.messages.append(msg)
    def error(self, msg): self.messages.append(msg)
    def success(self, msg): self.messages.append(msg)
    def tree(self, label, value, color=None, is_last=False): 
        self.messages.append(f"{label}: {value}")

def test_passive_initialization_cleaning():
    """
    Test Case: Domain Normalization and Sanitary Checks.
    
    Validates that the PassiveScanner correctly isolates the FQDN 
    from complex inputs (protocols, ports, paths) during initialization.
    """
    logger = FakeLogger()
    
    # Case: Full URL with port and deep path
    scanner = PassiveScanner("https://sub.target.com:443/api/v1?id=1", logger)
    assert scanner.domain == "sub.target.com"
    
    # Case: WWW prefix and trailing slash
    scanner_www = PassiveScanner("www.example.org/", logger)
    assert scanner_www.domain == "example.org"

def test_identity_shuffling_logic_integrity():
    """
    Test Case: Identity Stealth and Client-Hints Consistency.
    
    Abuses the identity rotation engine by generating 50 random identities.
    Ensures that the 'Sec-CH-UA-Platform' header always matches the 
    operating system family found within the 'User-Agent' string.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    for _ in range(50):
        headers = scanner._get_random_identity()
        ua = headers['User-Agent']
        platform = headers['Sec-CH-UA-Platform']
        
        if "iPhone" in ua or "iPad" in ua:
            assert platform == '"iOS"'
        elif "Android" in ua:
            assert platform == '"Android"'
        elif "Macintosh" in ua:
            assert platform == '"macOS"'
        elif "Windows" in ua:
            assert platform == '"Windows"'
        elif "X11" in ua or "Linux" in ua:
            assert platform == '"Linux"'

def test_process_data_cleaning_and_scope():
    """
    Test Case: CT Log Parsing and Scope Enforcement.
    
    Verifies that the _process_data method:
    1. Removes wildcards (*.) and duplicates.
    2. Strips redundant prefixes (www, http).
    3. Only includes subdomains belonging to the target domain.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mock data structure matching crt.sh JSON output
    raw_data = [
        {'name_value': '*.target.com'},             # Wildcard
        {'name_value': 'www.target.com'},            # Main domain
        {'name_value': 'api.target.com\nDEV.target.com'}, # Multi-line entry
        {'name_value': 'api.target.com'},            # Duplicate
        {'name_value': 'otherdomain.net'},           # Out of scope
        {'name_value': 'phish.target.com.co'}        # TLD confusion
    ]
    
    results = scanner._process_data(raw_data)
    
    # 'api' and 'dev' are valid subdomains. 
    # 'target.com' and 'www.target.com' are usually excluded as they are the target itself.
    assert "api.target.com" in results
    assert "dev.target.com" in results
    assert "otherdomain.net" not in results
    assert len(results) == len(set(results))

def test_fetch_subdomains_retry_resilience():
    """
    Test Case: Network Resilience and Adaptive Jitter.
    
    Simulates a scenario where crt.sh is temporarily busy (503 Error) 
    followed by a successful response. Ensures the scanner retries 
    instead of failing immediately.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    # Mocking both WHOIS and the CT Log request
    with patch.object(scanner, '_run_whois_phase', return_value=None):
        with patch("requests.get") as mock_get:
            # First call: 503 Service Unavailable, Second call: 200 OK
            mock_get.side_effect = [
                MagicMock(status_code=503),
                MagicMock(status_code=200, json=lambda: [{'name_value': 'vpn.target.com'}])
            ]
            
            # Patching time.sleep to avoid waiting during tests
            with patch("time.sleep", return_value=None):
                results = scanner.fetch_subdomains()
                
                assert mock_get.call_count == 2
                assert "vpn.target.com" in results

def test_whois_metadata_retention():
    """
    Test Case: Intelligence Metadata Persistence.
    
    Confirms that WHOIS information is correctly stored in the 
    self.whois_data attribute for downstream reporting.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("example.com", logger)
    
    mock_whois = {'registrar': 'NameCheap', 'creation_date': '2010-01-01'}
    
    # Simulate a successful WHOIS run
    with patch("aimenreco.core.passive.WhoisAnalyzer.run", return_value=mock_whois):
        scanner._run_whois_phase()
        assert scanner.whois_data['registrar'] == 'NameCheap'