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
    Normalizes a URL by removing trailing slashes, protocol prefixes, 
    and 'www.' to ensure consistent scanning.
    """
    if not url:
        return ""
        
    url = url.strip().lower()
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
        
    # Check if it already has a protocol
    has_protocol = url.startswith(('http://', 'https://'))
    
    # Remove protocol temporarily to clean the domain
    temp_url = url
    if url.startswith('http://'): temp_url = url[7:]
    elif url.startswith('https://'): temp_url = url[8:]
    
    # Remove 'www.'
    if temp_url.startswith('www.'):
        temp_url = temp_url[4:]
        
    # Reconstruct with original protocol or default to http
    if has_protocol:
        # Keep original protocol but with cleaned domain
        protocol = "http://" if url.startswith('http://') else "https://"
        return f"{protocol}{temp_url}"
    else:
        return f"http://{temp_url}"

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