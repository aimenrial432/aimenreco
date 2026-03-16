import pytest
from aimenreco.utils.helpers import clean_url

def test_clean_url_logic():
    """
    Verify that the URL cleaner handles various inputs correctly.
    """
    assert clean_url("google.com") == "http://google.com"
    assert clean_url("https://test.com/") == "https://test.com"