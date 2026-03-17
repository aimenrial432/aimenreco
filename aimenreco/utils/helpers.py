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
    
    Instead of loading the entire file into RAM, this function returns a 
    generator that yields one line at a time. This is critical for handling 
    massive dictionaries without memory exhaustion.

    Args:
        path (str): Absolute path to the wordlist file.

    Returns:
        generator: A generator object if the file exists.
        None: If the path is invalid or the file does not exist.
    """
    # IMMEDIATE VALIDATION: 
    # This ensures the function returns None immediately if the file is missing,
    # satisfying the strengh requirements of the test suite.
    if not path or not os.path.exists(path):
        return None

    def generator_logic():
        """Internal generator logic to be returned after path validation."""
        try:
            # Using 'ignore' for errors to handle non-UTF8 characters in massive wordlists
            with open(path, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    # Skip empty lines and common wordlist comments (#)
                    if word and not word.startswith("#"):
                        yield word
        except Exception:
            return

    # Return the generator object only after the path has been verified
    return generator_logic()
    
def prepare_wordlist(path, logger):
    """
    Locates the wordlist file and calculates basic metadata.
    
    Checks both the provided path and the internal resources directory.
    Returns the absolute path and an estimated word count.
    
    :param path: Initial path or filename of the wordlist.
    :param logger: Logger instance to report errors.
    :return: Tuple (absolute_path, word_count) or (None, 0) if not found.
    """
    if not os.path.exists(path):
        from .helpers import get_resource_path
        path = get_resource_path(path)

    if not os.path.exists(path):
        logger.error(f"Wordlist '{path}' not found.")
        return None, 0

    file_size = os.path.getsize(path)
    # Estimated word count based on average line length
    word_count = file_size // 12 
    return path, word_count