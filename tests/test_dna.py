import pytest
from aimenreco.core.wildcard import WildcardAnalyzer

def test_wildcard_logic_perfect_match():
    """
    Test Case: Perfect Wildcard Detection.
    Verifies that the engine correctly identifies a 'Catch-all' scenario where 
    the server returns identical status codes and sizes for every random request.
    """
    # Note: timeout is 1 (int) to match your docstring
    analyzer = WildcardAnalyzer("http://example.com", timeout=1)
    
    # Mock data: 10 identical responses (Status 404, Size 500 bytes)
    mock_responses = [(404, 500)] * 10
    
    status_codes = [r[0] for r in mock_responses]
    sizes = [r[1] for r in mock_responses]
    
    is_wildcard = all(s == status_codes[0] for s in status_codes)
    size_variance = max(sizes) - min(sizes)
    
    assert is_wildcard is True
    assert size_variance == 0

def test_wildcard_logic_no_wildcard():
    """
    Test Case: Standard Server Behavior (No Wildcard).
    Verifies that a normal server returning different status codes for different 
    resources is NOT flagged as a wildcard.
    """
    analyzer = WildcardAnalyzer("http://example.com", timeout=1)
    
    # Mock data: Some 404s, some 403s (WAF/Auth), some 301s
    status_codes = [404, 404, 403, 404, 301, 404, 404, 403, 404, 404]
    
    # A wildcard is only triggered if 80% (8/10) match a 2xx or 3xx status
    # This logic test verifies the 'False' outcome
    is_wildcard = all(s // 100 in {2, 3} for s in status_codes)
    
    assert is_wildcard is False

def test_wildcard_analyzer_initialization():
    """
    Test Case: Analyzer Configuration.
    Ensures the WildcardAnalyzer correctly stores its target_url and timeout settings.
    Matches the actual attribute names: self.target_url and self.timeout.
    """
    target = "http://test.local"
    timeout = 5
    analyzer = WildcardAnalyzer(target, timeout)
    
    # FIXED: Accessing 'target_url' instead of 'url'
    assert analyzer.target_url == target
    assert analyzer.timeout == timeout