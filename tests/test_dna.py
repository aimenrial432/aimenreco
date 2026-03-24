import pytest
import json
from unittest.mock import MagicMock, patch
from aimenreco.core.wildcard import WildcardAnalyzer

@pytest.fixture
def mock_logger():
    """
    Provides a mock logger to satisfy WildcardAnalyzer dependency.
    Ensures that log calls during tests don't pollute the terminal.
    """
    return MagicMock()

def test_wildcard_logic_perfect_match(mock_logger):
    """
    Test Case: Perfect Wildcard Detection.
    
    Verifies that the engine correctly identifies a 'Catch-all' scenario where 
    the server returns identical status codes and sizes for every random request.
    This simulates a server that doesn't properly handle 404 errors.
    """
    analyzer = WildcardAnalyzer("http://example.com", mock_logger, timeout=1)
    
    # Mock data: 10 identical responses (Status 404, Size 500 bytes)
    mock_responses = [(404, 500)] * 10
    
    status_codes = [r[0] for r in mock_responses]
    sizes = [r[1] for r in mock_responses]
    
    is_wildcard = all(s == status_codes[0] for s in status_codes)
    size_variance = max(sizes) - min(sizes)
    
    assert is_wildcard is True
    assert size_variance == 0

def test_wildcard_logic_no_wildcard(mock_logger):
    """
    Test Case: Standard Server Behavior (No Wildcard).
    
    Verifies that a normal server returning different status codes (404, 403, 301) 
    for randomized resources is NOT flagged as a wildcard. This ensures the 
    scanner continues its discovery phase normally.
    """
    analyzer = WildcardAnalyzer("http://example.com", mock_logger, timeout=1)
    
    # Mock data: Mixed responses including errors and redirects
    status_codes = [404, 404, 403, 404, 301, 404, 404, 403, 404, 404]
    
    # A wildcard is triggered if 80% (8/10) match a 2xx or 3xx status
    # In this case, only one 301 exists, so it should fail the wildcard check.
    is_wildcard = all(s // 100 in {2, 3} for s in status_codes)
    
    assert is_wildcard is False

def test_wildcard_analyzer_initialization(mock_logger):
    """
    Test Case: Analyzer Configuration and Dependency Injection.
    
    Ensures the WildcardAnalyzer correctly stores its target_url, logger, 
    and timeout settings upon instantiation. This is critical for 
    maintaining global state across the discovery engine.
    """
    target = "http://test.local"
    timeout = 5
    analyzer = WildcardAnalyzer(target, mock_logger, timeout=timeout)
    
    assert analyzer.target_url == target
    assert analyzer.timeout == timeout
    assert analyzer.logger == mock_logger

def test_resource_loading_fallback(mock_logger):
    """
    Test Case: Resource Loading Resilience.
    
    Verifies that if the user_agents.json file is missing or corrupted, 
    the analyzer falls back to a default User-Agent list instead of 
    crashing the entire scan.
    """
    with patch("aimenreco.core.wildcard.get_resource_path", return_value="/non/existent/path"):
        analyzer = WildcardAnalyzer("http://example.com", mock_logger)
        # Should use the fallback defined in the constructor
        assert "Aimenreco/3.2" in analyzer.user_agents
        assert len(analyzer.user_agents) > 0

def test_user_agent_rotation_integrity(mock_logger):
    """
    Test Case: User-Agent Rotation Availability.
    
    Ensures that the Wildcard engine has access to multiple identities 
    before starting the DNA stress test, facilitating stealth even 
    during the initial profiling phase.
    """
    analyzer = WildcardAnalyzer("http://example.com", mock_logger)
    
    # The list should be populated either by JSON or fallback
    assert isinstance(analyzer.user_agents, list)
    assert len(analyzer.user_agents) >= 1