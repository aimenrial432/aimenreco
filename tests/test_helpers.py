import os
import re
from typing import Generator

def clean_url(url: str) -> str:
    """
    Normalizes a URL by removing trailing slashes, spaces, and 'www',
    while ensuring a default protocol.
    """
    url = url.strip().lower()
    if not url:
        return ""
    
    # Add default protocol if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    # Remove trailing slashes
    url = url.rstrip("/")
    
    # Remove www.
    url = url.replace("://www.", "://")
    
    return url

def stream_wordlist(filepath: str) -> Generator[str, None, None]:
    """
    Yields non-empty, non-comment lines from a file.
    If the file doesn't exist, it yields nothing (empty generator).
    """
    if not os.path.exists(filepath):
        # Instead of returning None, we return an empty generator
        return
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(("#", "//")):
                yield line

def get_resource_path(filename: str) -> str:
    """
    Constructs the absolute path to a file within the package's resources directory.
    """
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, "resources", filename)