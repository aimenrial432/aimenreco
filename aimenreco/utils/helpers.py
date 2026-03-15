#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

def get_resource_path(relative_path):
    """
    Locates resources within the 'resources' directory relative to the package.
    
    This function calculates the absolute path of the project to ensure 
    resource availability regardless of the current working directory 
    from which the command is executed.

    Args:
        relative_path (str): The name or relative path of the resource file.

    Returns:
        str: The absolute path to the requested resource.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    return os.path.join(project_root, "resources", relative_path)

def clean_url(url):
    """
    Sanitizes the target URL for the scanning engine.
    
    Removes whitespace, trailing slashes, and ensures a valid 
    HTTP/HTTPS protocol prefix. This prevents malformed requests when 
    appending paths from the wordlist.

    Args:
        url (str): The raw input URL.

    Returns:
        str: A sanitized URL string without trailing slashes.
    """
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        # Defaulting to HTTP if no protocol is specified.
        url = f"http://{url}"
    return url

def stream_wordlist(path):
    """
    Memory-efficient wordlist loader using Python generators.
    
    Instead of loading the entire file into RAM, this function yields 
    one line at a time. This is critical for handling massive 
    dictionaries (e.g., millions of lines) without memory exhaustion.

    Args:
        path (str): Absolute path to the wordlist file.

    Yields:
        str: The next cleaned word/path from the file, skipping comments.
    """
    if not os.path.exists(path):
        return None
    
    try:
        # Using 'ignore' for errors to handle non-UTF8 characters in massive wordlists
        with open(path, 'r', encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                # Skip empty lines and common wordlist comments (#)
                if word and not word.startswith("#"):
                    yield word
    except Exception:
        return None