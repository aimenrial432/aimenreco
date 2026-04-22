#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass(frozen=True)
class ScanConfig:
    """
    Configuration settings for the scanning engine.
    
    Attributes:
        target (str): The base URL or IP to scan.
        threads (int): Number of concurrent worker threads.
        timeout (float): Request timeout in seconds.
        wordlist_path (str): Filesystem path to the dictionary file.
        mode (str): Execution mode (e.g., 'STD', 'BRUTE', 'PASSIVE').
        user_agent (str): Custom HTTP User-Agent string.
    """
    target: str
    threads: int
    timeout: float
    wordlist_path: str
    mode: str = "STD"
    user_agent: str = "Aimenreco/3.3"


@dataclass
class ScanResult:
    """
    Represents the outcome of a single HTTP resource discovery attempt.
    
    Attributes:
        url (str): The full URL of the discovered resource.
        status_code (int): HTTP response status code.
        content_length (int): Size of the response body in bytes.
        title (Optional[str]): HTML page title if available.
        redirect_url (Optional[str]): Target URL if a redirection (3xx) occurred.
        headers (Dict[str, str]): Key-Value pairs of HTTP response headers.
    """
    url: str
    status_code: int
    content_length: int
    title: Optional[str] = None
    redirect_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class WildcardDNA:
    """
    Captured behavior of a server's response to non-existent resources.
    
    Attributes:
        enabled (bool): Whether wildcard/catch-all behavior was detected.
        base_hash (Optional[str]): MD5 fingerprint of the default error page.
        size (int): The consistent body size (average) for dead links.
        status (int): The consistent status code returned for dead links.
        redirect_loc (Optional[str]): Common redirection target if applicable.
    """
    enabled: bool
    base_hash: Optional[str]
    size: int
    status: int
    redirect_loc: Optional[str] = None