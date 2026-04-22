#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import Optional, Tuple, Generator, Any
from aimenreco.ui.logger import Logger

def get_resource_path(relative_path: str) -> str:
    """
    Locates resources within the 'resources' directory relative to the package.
    
    Ensures resource availability regardless of the current working directory 
    from which the command is executed.

    Args:
        relative_path: The name or relative path of the resource file.

    Returns:
        The absolute path to the requested resource.
    """
    current_dir: str = os.path.dirname(os.path.abspath(__file__))
    # Assuming helpers is inside a subfolder like 'utils', we go up to project root
    project_root: str = os.path.dirname(current_dir)
    return os.path.join(project_root, "resources", relative_path)

def clean_url(url: Optional[str]) -> str:
    """
    Normalizes a URL by removing trailing slashes, protocol prefixes, 
    and 'www.' to ensure consistent scanning.
    
    Args:
        url: The raw URL/domain string.
        
    Returns:
        A normalized URL string starting with http:// or https://.
    """
    if not url:
        return ""
        
    url = url.strip().lower()
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
        
    # Check original protocol
    has_protocol: bool = url.startswith(('http://', 'https://'))
    
    # Extract domain without protocol
    temp_url: str = url
    if url.startswith('http://'): 
        temp_url = url[7:]
    elif url.startswith('https://'): 
        temp_url = url[8:]
    
    # Remove 'www.' prefix
    if temp_url.startswith('www.'):
        temp_url = temp_url[4:]
        
    # Reconstruct: default to http:// if no protocol was provided
    if has_protocol:
        protocol: str = "http://" if url.startswith('http://') else "https://"
        return f"{protocol}{temp_url}"
    else:
        return f"http://{temp_url}"

def stream_wordlist(path: str) -> Optional[Generator[str, Any, None]]:
    """
    Memory-efficient wordlist loader using Python generators.
    
    Critical for handling massive dictionaries without memory exhaustion.

    Args:
        path: Absolute path to the wordlist file.

    Returns:
        A generator yielding words or None if the file is invalid.
    """
    if not path or not os.path.exists(path):
        return None

    def generator_logic() -> Generator[str, Any, None]:
        try:
            # 'errors="ignore"' handles non-UTF8 characters in massive wordlists
            with open(path, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word: str = line.strip()
                    # Skip empty lines and common wordlist comments
                    if word and not word.startswith("#"):
                        yield word
        except Exception:
            return

    return generator_logic()
    
def prepare_wordlist(path: str, logger: Logger) -> Tuple[Optional[str], int]:
    """
    Locates the wordlist file and calculates basic metadata.
    
    Args:
        path: Initial path or filename of the wordlist.
        logger: Logger instance to report errors.
        
    Returns:
        A tuple of (absolute_path, estimated_word_count).
    """
    # Try direct path first, then check resources
    if not os.path.exists(path):
        resource_path: str = get_resource_path(path)
        if os.path.exists(resource_path):
            path = resource_path

    if not os.path.exists(path):
        logger.error(f"Wordlist '{path}' not found.")
        return None, 0

    try:
        file_size: int = os.path.getsize(path)
        # Estimated word count (avg 12 chars per line including \n)
        word_count: int = file_size // 12 
        return path, word_count
    except OSError:
        logger.error(f"Could not access wordlist at {path}")
        return None, 0