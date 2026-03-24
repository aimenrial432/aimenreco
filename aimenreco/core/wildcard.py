#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import hashlib
import json
from collections import Counter
from aimenreco.ui.colors import YELLOW, GREY, WHITE, CYAN, RED, RESET, GREEN
from aimenreco.utils.helpers import get_resource_path

# Suppress insecure request warnings for local/lab testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WildcardAnalyzer:
    """
    Network DNA Analyzer for Catch-all and Wildcard behavior identification.

    This engine profiles the target's response patterns by performing a 10-point 
    stress test. It identifies universal redirect rules, custom error pages, 
    and fingerprinting stability, allowing the discovery engine to filter out 
    persistent false positives during the active phase.
    """

    def __init__(self, target_url, logger, timeout=5):
        """
        Initializes the analyzer with target connection parameters and logger.

        Args:
            target_url (str): Target base URL.
            logger (Logger): Centralized logging instance.
            timeout (int): Seconds to wait for server response.
        """
        self.target_url = target_url
        self.logger = logger
        self.timeout = timeout
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.2"])

    def _load_json_resource(self, filename, fallback):
        """
        Internal helper to load JSON data from package resources.

        Args:
            filename (str): Name of the resource file.
            fallback (list): Default list if file is missing.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def check(self):
        """
        Executes a 10-point DNA stress test to identify stability and wildcards.

        Detection Logic:
            - Performs 10 requests to randomized non-existent paths.
            - Statistical Consistency: Requires 80% similarity in status and size.
            - Fingerprinting: Captures MD5 hash, status code, and location headers.
            - Adaptive Filtering: Marks as "Wildcard" if the server masks 404s with 2xx/3xx,
              or stores the base 404 DNA if the response is consistent.

        Returns:
            tuple: (is_wildcard: bool, base_hash: str, avg_size: int, base_status: int, redirect_loc: str).
        """
        metrics = []
        self.logger.info(f"{YELLOW}[*] Analyzing network DNA (10 Stress Tests):{RESET}")
        
        try:
            for i in range(1, 11):
                random_path = f"wildcard_{random.getrandbits(24)}"
                test_url = f"{self.target_url}/{random_path}"
                
                try:
                    headers = {"User-Agent": random.choice(self.user_agents)}
                    # allow_redirects=False captures the true first-hop behavior
                    r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                     allow_redirects=False, verify=False)
                    
                    c_hash = hashlib.md5(r.content).hexdigest()
                    size = len(r.content)
                    loc = r.headers.get("Location", "")
                    
                    msg = (f"{GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
                           f"Status: {CYAN}{r.status_code}{RESET} | Size: {CYAN}{size}{RESET}")
                    self.logger.info(f"  {msg}")
                    
                    metrics.append({
                        'size': size, 
                        'hash': c_hash, 
                        'status': r.status_code,
                        'location': loc
                    })
                except requests.exceptions.RequestException:
                    self.logger.error(f"  DNA Test {i:02d} failed: Connection Error")
                    continue

            if not metrics:
                return False, None, 0, 0, None

            # --- STATISTICAL ANALYSIS ---
            status_codes = [m['status'] for m in metrics]
            s_counts = Counter(status_codes)
            m_status, s_count = s_counts.most_common(1)[0]
            
            # Logic: If 80% of requests return the SAME behavior, we have a stable DNA.
            if s_count >= 8:
                h_counts = Counter([m['hash'] for m in metrics])
                m_hash = h_counts.most_common(1)[0][0]
                
                l_counts = Counter([m['location'] for m in metrics])
                m_loc = l_counts.most_common(1)[0][0]
                
                avg_size = sum([m['size'] for m in metrics]) / len(metrics)
                
                # Check if it's a "Dangerous" Wildcard (Masking errors with 200 or 302)
                if (m_status // 100) in {2, 3}:
                    self.logger.info(f"\n  {RED}[!] WILDCARD DETECTED (Common Status: {m_status}){RESET}")
                    return True, m_hash, int(avg_size), m_status, m_loc
                
                # If it's a stable 404 (like your 808 bytes), we still return True 
                # so the Scanner knows what to filter as "Normal Error".
                self.logger.info(f"\n  {GREEN}[✓] Stable 404 DNA identified (Size: {int(avg_size)}).{RESET}\n")
                return True, m_hash, int(avg_size), m_status, m_loc
            
            # Unstable behavior: No clear pattern found
            self.logger.info(f"\n  {YELLOW}[!] Unstable DNA: Multiple response patterns detected.{RESET}\n")
            return False, None, 0, 0, None

        except KeyboardInterrupt:
            from aimenreco.utils.exceptions import UserAbortException
            raise UserAbortException()
        except Exception as e:
            self.logger.error(f"DNA Analysis Error: {e}")
            return False, None, 0, 0, None