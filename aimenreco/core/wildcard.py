#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import hashlib
import json
from collections import Counter

from aimenreco.ui.colors import YELLOW, GREY, WHITE, CYAN, RED, RESET, GREEN
from aimenreco.utils.helpers import get_resource_path

class WildcardAnalyzer:
    """
    Network DNA Analyzer for Catch-all and Wildcard behavior identification.

    This engine performs heuristic analysis of the target's response patterns 
    to identify universal redirect rules or custom error pages that don't 
    return a 404 status. This prevents the enumeration engine from reporting 
    thousands of false positives.

    Attributes:
        target_url (str): The base URL to analyze.
        timeout (int): Request timeout for DNA tests.
        user_agents (list): Pool of User-Agent strings to rotate during tests.
    """

    def __init__(self, target_url, timeout=5):
        """
        Initializes the analyzer with target connection parameters.

        Args:
            target_url (str): Target base URL.
            timeout (int, optional): Seconds to wait for server. Defaults to 5.
        """
        self.target_url = target_url
        self.timeout = timeout
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.0"])

    def _load_json_resource(self, filename, fallback):
        """
        Loads supporting JSON resources for the analysis phase.

        Args:
            filename (str): JSON file name.
            fallback (any): Data to return in case of I/O or parsing error.

        Returns:
            dict/list: Loaded data or fallback.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def check(self):
        """
        Executes a 10-point DNA stress test to identify Wildcard patterns.

        The algorithm works by:
        1. Requesting 10 non-existent random paths.
        2. Collecting status codes, content hashes (MD5), and response sizes.
        3. Statistical Analysis: If >80% of responses share an 'alive' status 
           (200, 301, 302), a Wildcard is confirmed.
        4. Fingerprinting: Calculates a baseline average size and hash to 
           filter future requests in the Scanner module.

        Returns:
            tuple: (is_wildcard: bool, base_hash: str, average_size: int).
        """
        metrics = []
        print(f"{YELLOW}[*] Analyzing network metrics (10 DNA Stress Tests):{RESET}")
        
        for i in range(1, 11):
            # Generate entropy for non-existent paths
            random_path = f"wildcard_{random.getrandbits(24)}"
            test_url = f"{self.target_url}/{random_path}"
            try:
                headers = {"User-Agent": random.choice(self.user_agents)}
                # allow_redirects=False is crucial to catch the initial redirect hop
                r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                 allow_redirects=False, verify=False)
                
                c_hash = hashlib.md5(r.content).hexdigest()
                size = len(r.content)
                
                print(f"  {GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
                      f"Status: {CYAN}{r.status_code}{RESET} | Size: {CYAN}{size}{RESET}")
                
                metrics.append({'size': size, 'hash': c_hash, 'status': r.status_code})
            except Exception as e:
                print(f"  {RED}[!] DNA Test {i:02d} failed: {e}{RESET}")

        if not metrics:
            return False, None, 0

        # Heuristic Logic
        status_codes = [m['status'] for m in metrics]
        s_counts = Counter(status_codes)
        m_status, s_count = s_counts.most_common(1)[0]
        
        # If 80% or more of random paths return a success/redirect status
        if s_count >= 8 and m_status in {200, 301, 302}:
            h_counts = Counter([m['hash'] for m in metrics])
            m_hash = h_counts.most_common(1)[0][0]
            avg_size = sum([m['size'] for m in metrics]) / len(metrics)
            
            print(f"\n  {RED}[!] WILDCARD DETECTED (Common Status: {m_status}){RESET}")
            return True, m_hash, int(avg_size)
        
        print(f"\n  {GREEN}[✓] Stable Server: No Wildcard patterns detected.{RESET}\n")
        return False, None, 0