import pytest
from aimenreco.core.passive import PassiveScanner

class FakeLogger:
    """Mock logger for passive reconnaissance testing."""
    def __init__(self):
        self.messages = []
        self.quiet = False
    def info(self, msg): self.messages.append(msg)
    def warn(self, msg): self.messages.append(msg)
    def error(self, msg): self.messages.append(msg)

def test_passive_initialization_cleaning():
    """
    Ensure PassiveScanner extracts the root domain correctly 
    regardless of the user's input format (URLs, protocols, or paths).
    """
    logger = FakeLogger()
    
    # Case 1: URL with protocol and path
    scanner1 = PassiveScanner("https://sub.example.com/api", logger)
    assert scanner1.domain == "sub.example.com"
    
    # Case 2: Hostname with 'www' and trailing slash
    scanner2 = PassiveScanner("www.target.org/", logger)
    assert scanner2.domain == "target.org"

def test_process_data_deduplication():
    """
    Check the normalization and deduplication of CT Log records.
    Verifies that wildcards are stripped and subdomains are properly filtered.
    """
    logger = FakeLogger()
    scanner = PassiveScanner("example.com", logger)
    
    # Simulated raw data from crt.sh including noise and duplicates
    raw_data = [
        {'name_value': '*.example.com'},
        {'name_value': 'www.example.com'},
        {'name_value': 'api.example.com\nVPN.EXAMPLE.COM'}
    ]
    
    results = scanner._process_data(raw_data)
    
    # Should normalize everything to lowercase and remove wildcard/www prefixes
    assert "api.example.com" in results
    assert "vpn.example.com" in results
    assert "example.com" not in results  # Root domain should be excluded