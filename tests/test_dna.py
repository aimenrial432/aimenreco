import pytest
from typing import List, Any
from aimenreco.core.wildcard import WildcardAnalyzer
from aimenreco.models import WildcardDNA

def test_wildcard_dna_structure_integrity(mocker: Any, logger: Any) -> None:
    """
    Test Case: DNA Model Validation.
    
    Verifies that the analyzer returns a valid 5-tuple that can be
    correctly mapped to the WildcardDNA dataclass.
    """
    # Usamos mocker en lugar de patch manual
    mock_get = mocker.patch('requests.get')
    
    mock_response = mocker.Mock()
    mock_response.status_code = 404
    mock_response.content = b"DNA_TEST_CONTENT"
    mock_response.text = "DNA_TEST_CONTENT"
    mock_response.headers = {"Location": "http://redirect.com"}
    mock_get.return_value = mock_response

    analyzer = WildcardAnalyzer("http://example.com", logger, timeout=1)
    
    result = analyzer.check()
    w_data = WildcardDNA(*result)

    assert isinstance(w_data.enabled, bool)
    assert w_data.status == 404
    assert w_data.size == len(b"DNA_TEST_CONTENT")
    assert w_data.redirect_loc == "http://redirect.com"

def test_wildcard_analyzer_initialization(logger: Any) -> None:
    """
    Test Case: Analyzer Configuration and Dependency Injection.
    """
    target: str = "http://test.local"
    analyzer = WildcardAnalyzer(target, logger, timeout=5)
    
    assert analyzer.target_url == target
    assert analyzer.logger == logger

def test_resource_loading_fallback(mocker: Any, logger: Any) -> None:
    """
    Test Case: Resource Loading Resilience.
    """
    mocker.patch("aimenreco.core.wildcard.get_resource_path", return_value="/non/existent/path")
    
    analyzer = WildcardAnalyzer("http://example.com", logger)
    assert any("Aimenreco" in ua for ua in analyzer.user_agents)

def test_user_agent_rotation_is_random(mocker: Any, logger: Any) -> None:
    """
    Test Case: Identity Rotation and Header Injection.
    """
    analyzer = WildcardAnalyzer("http://example.com", logger)
    test_uas: List[str] = ["UA_1", "UA_2", "UA_3"]
    analyzer.user_agents = test_uas

    mock_get = mocker.patch('requests.get')
    mock_get.return_value = mocker.Mock(status_code=404, content=b"", text="", headers={})
    
    analyzer.check()

# Verify that User-Agents were successfully rotated across the 10 stress test requests
    sent_uas = [call.kwargs['headers']['User-Agent'] for call in mock_get.call_args_list]
    assert len(sent_uas) == 10
    for ua in sent_uas:
        assert ua in test_uas