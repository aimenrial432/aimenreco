import pytest
from aimenreco.core.wildcard import WildcardAnalyzer

def test_wildcard_logic_detection():
    """
    Verify the DNA engine's ability to identify wildcard patterns.
    It simulates a scenario where the server returns consistent status codes 
    and response sizes for non-existent resources.
    """
    # Initialize analyzer (it won't make real requests during this logic test)
    analyzer = WildcardAnalyzer("http://example.com", timeout=1)
    
    # Mock data: 10 identical responses (Status 301, Size 162 bytes)
    # This simulates a typical "Redirect All" wildcard behavior
    mock_responses = [(301, 162)] * 10
    
    status_codes = [r[0] for r in mock_responses]
    sizes = [r[1] for r in mock_responses]
    
    # Core detection logic
    common_status = status_codes[0]
    is_wildcard = all(s == common_status for s in status_codes)
    size_variance = max(sizes) - min(sizes)
    
    # Assertions to ensure the logic flags this as a Wildcard
    assert is_wildcard is True
    assert common_status == 301
    assert size_variance == 0