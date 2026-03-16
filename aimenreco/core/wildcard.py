#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import hashlib
import json
import sys
from collections import Counter

from aimenreco.ui.colors import YELLOW, GREY, WHITE, CYAN, RED, RESET, GREEN
from aimenreco.utils.helpers import get_resource_path

# Suppress insecure request warnings for local/lab testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WildcardAnalyzer:
    """
    Network DNA Analyzer for Catch-all and Wildcard behavior identification.

    This engine performs heuristic analysis of the target's response patterns 
    to identify universal redirect rules (e.g., Cloudflare, HSTS) or custom 
    error pages. It benchmarks the 'baseline' behavior of a target to calibrate 
    the discovery engine and filter out persistent false positives.
    """

    def __init__(self, target_url, timeout=5):
        """
        Initializes the analyzer with target connection parameters.

        Args:
            target_url (str): Target base URL.
            timeout (int, optional): Seconds to wait for server response. Defaults to 5.
        """
        self.target_url = target_url
        self.timeout = timeout
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.2"])

    def _load_json_resource(self, filename, fallback):
        """
        Loads supporting JSON resources for the analysis phase.
        
        Args:
            filename (str): Name of the JSON file.
            fallback (list/dict): Data to return if the file is missing.
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

        The algorithm performs statistical profiling of non-existent paths to 
        identify stable response characteristics (MD5 hashes, size variance, locations).
        
        Detection Logic:
            - Performs 10 requests to randomized paths.
            - Status Class Filtering: Triggers if status code is 2xx or 3xx.
            - Statistical Stability: Requires 80% (8/10) consistency.

        Returns:
            tuple: (is_wildcard: bool, base_hash: str, avg_size: int, base_status: int, redirect_loc: str).
        """
        metrics = []
        print(f"{YELLOW}[*] Analyzing network metrics (10 DNA Stress Tests):{RESET}")
        
        try:
            for i in range(1, 11):
                random_path = f"wildcard_{random.getrandbits(24)}"
                test_url = f"{self.target_url}/{random_path}"
                
                try:
                    headers = {"User-Agent": random.choice(self.user_agents)}
                    # Manual redirect handling (allow_redirects=False) is crucial for fingerprinting
                    r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                     allow_redirects=False, verify=False)
                    
                    c_hash = hashlib.md5(r.content).hexdigest()
                    size = len(r.content)
                    loc = r.headers.get("Location", "")
                    
                    print(f"  {GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
                          f"Status: {CYAN}{r.status_code}{RESET} | Size: {CYAN}{size}{RESET}")
                    
                    metrics.append({
                        'size': size, 
                        'hash': c_hash, 
                        'status': r.status_code,
                        'location': loc
                    })
                except requests.exceptions.RequestException as e:
                    print(f"  {RED}[!] DNA Test {i:02d} failed: Connection Error{RESET}")
                    continue

            if not metrics:
                return False, None, 0, 0, None

            # --- STATISTICAL ANALYSIS ---
            # Extract most frequent status code
            status_codes = [m['status'] for m in metrics]
            s_counts = Counter(status_codes)
            m_status, s_count = s_counts.most_common(1)[0]
            
            status_class = m_status // 100
            
            # Heuristic: If 80% of requests return a success/redirect instead of 404.
            if s_count >= 8 and status_class in {2, 3}:
                # Calculate predominant Fingerprint (MD5)
                h_counts = Counter([m['hash'] for m in metrics])
                m_hash = h_counts.most_common(1)[0][0]
                
                # Identify if there is a common redirection sinkhole
                l_counts = Counter([m['location'] for m in metrics])
                m_loc = l_counts.most_common(1)[0][0]
                
                # Average size calculation for variance-based filtering (±15 bytes in Scanner)
                avg_size = sum([m['size'] for m in metrics]) / len(metrics)
                
                print(f"\n  {RED}[!] WILDCARD DETECTED (Common Status: {m_status}){RESET}")
                if m_loc:
                    print(f"  {GREY}[i] Predominant redirection target: {m_loc}{RESET}")

                return True, m_hash, int(avg_size), m_status, m_loc
            
            # If no wildcard pattern is found
            print(f"\n  {GREEN}[✓] Stable Server: No Wildcard patterns detected.{RESET}\n")
            return False, None, 0, 0, None

        except KeyboardInterrupt:
            # Clean exit on user interruption during testing
            from aimenreco.utils.exceptions import UserAbortException
            raise UserAbortException()
        
        except (requests.exceptions.RequestException, Exception) as e:
            # We must check if 'e' is our custom exception to avoid catching it here
            from aimenreco.utils.exceptions import UserAbortException
            if isinstance(e, UserAbortException):
                raise e
                
            print(f"\n{RED}[!] Critical Error during DNA analysis: {e}{RESET}")
            return False, None, 0, 0, None