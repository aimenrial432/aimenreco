import pytest
from aimenreco.core.passive import PassiveScanner

class FakeLogger:
    """
    Mock logger for passive reconnaissance testing.
    Records messages to verify internal logging behavior.
    """
    def __init__(self):
        self.messages = []
        self.quiet = False
        self.verbose = False
    def info(self, msg): self.messages.append(msg)
    def warn(self, msg): self.messages.append(msg)
    def error(self, msg): self.messages.append(msg)

def test_passive_initialization_cleaning():
    """
    Test Case: Domain Normalization.
    Ensures PassiveScanner extracts the clean root domain regardless 
    of protocols, subdirectories, or 'www' prefixes in the input.
    """
    logger = FakeLogger()
    
    # Case 1: Complex URL with protocol, port and path
    scanner1 = PassiveScanner("https://sub.example.com:8443/api/v1", logger)
    # The scanner should strip everything but the relevant hostname
    assert scanner1.domain == "sub.example.com"
    
    # Case 2: Hostname with 'www' and trailing slash
    scanner2 = PassiveScanner("www.target.org/", logger)
    assert scanner2.domain == "target.org"

def test_process_data_deduplication():
    """
    Test Case: CT Log Data Normalization.
    Verifies that the engine correctly processes raw JSON from crt.sh:
    - Strips wildcard prefixes (*.)
    - Removes 'www.' prefixes for consistency.
    - Handles multi-line entries.
    - Normalizes to lowercase.
    - Removes duplicates.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("example.com", logger)
    
    # Simulated messy data from Certificate Transparency logs
    raw_data = [
        {'name_value': '*.example.com'},              # Wildcard
        {'name_value': 'WWW.EXAMPLE.COM'},            # Uppercase + WWW
        {'name_value': 'api.example.com\nVPN.example.com'}, # Multi-line entry
        {'name_value': 'api.example.com'}             # Duplicate
    ]
    
    results = scanner._process_data(raw_data)
    
    # Assertions for expected clean output
    assert "api.example.com" in results
    assert "vpn.example.com" in results
    assert "example.com" in results or "www.example.com" not in results
    
    # Verify duplicates were merged (lowercase comparison)
    assert len(results) == len(set(results))

def test_passive_scanner_empty_results():
    """
    Test Case: Resilience to Empty Data.
    Ensures the scanner handles cases where no certificates are found 
    without raising exceptions.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("nonexistent-domain-12345.com", logger)
    
    # Empty list from a mock API response
    results = scanner._process_data([])
    
    assert isinstance(results, list)
    assert len(results) == 0

def test_passive_domain_validation():
    """
    Test Case: Domain Filtering.
    Ensures the scanner only keeps subdomains that actually belong 
    to the target domain, filtering out accidental out-of-scope leaks.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("target.com", logger)
    
    raw_data = [
        {'name_value': 'sub.target.com'},
        {'name_value': 'malicious-phishing-target.com.other.net'}, # Out of scope
        {'name_value': 'target.com.co'} # Different TLD
    ]
    
    results = scanner._process_data(raw_data)
    
    assert "sub.target.com" in results
    assert "target.com.co" not in results
    assert "malicious-phishing-target.com.other.net" not in results