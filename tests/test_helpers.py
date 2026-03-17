import os
import pytest
from aimenreco.utils.helpers import clean_url, stream_wordlist, get_resource_path

def test_clean_url_robustness():
    """
    Test Case: URL Normalization.
    Verifies that the cleaner handles protocols, trailing slashes, 
    'www' subdomains, and mixed casing consistently.
    """
    # Standard normalization
    assert clean_url("google.com") == "http://google.com"
    assert clean_url("HTTPS://TEST.COM/") == "https://test.com"
    
    # WWW removal while preserving protocol
    assert clean_url("https://www.target.org") == "https://target.org"
    assert clean_url("www.example.net/path/") == "http://example.net/path"
    
    # Complex cases
    assert clean_url("  http://MySite.com  ") == "http://mysite.com"
    assert clean_url("") == ""

def test_stream_wordlist_logic(tmp_path):
    """
    Test Case: Memory-Efficient Wordlist Streaming.
    Ensures the generator skips comments, empty lines, and handles 
    whitespace correctly without loading the whole file into RAM.
    """
    # Create a dummy wordlist
    d = tmp_path / "test_list.txt"
    content = "admin\n  \n# this is a comment\npassword\n\nroot  \n"
    d.write_text(content)
    
    words = list(stream_wordlist(str(d)))
    
    # Expected: ['admin', 'password', 'root']
    assert len(words) == 3
    assert "admin" in words
    assert "password" in words
    assert "root" in words
    assert "# this is a comment" not in words
    assert "" not in words

def test_get_resource_path_logic():
    """
    Test Case: Resource Location.
    Verifies that the resource locator returns an absolute path 
    pointing to the 'resources' directory.
    """
    path = get_resource_path("user_agents.json")
    
    assert os.path.isabs(path)
    assert "resources" in path
    assert path.endswith("user_agents.json")

def test_stream_wordlist_nonexistent_file():
    """
    Test Case: Error Handling for Missing Files.
    Ensures that trying to stream a non-existent wordlist 
    returns None or handles it gracefully instead of crashing.
    """
    gen = stream_wordlist("/tmp/non_existent_file_12345.txt")
    assert gen is None