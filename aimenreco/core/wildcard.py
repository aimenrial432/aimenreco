#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
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

    def __init__(self, target_url, logger, timeout: float = 5):
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

    def _extract_title(self, html):
        """
        Extracts the content of the HTML <title> tag.

        Args:
            html (str): Raw HTML response body.
        
        Returns:
            str: The sanitized title or 'No Title' if not found.
        """
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()[:30] # Truncate for clean UI
        return "No Title"

    def check(self, verbose_level=0):
        """
        Executes a 10-point DNA stress test to identify stability and wildcards.

        Detection Logic:
            - Performs 10 requests to randomized non-existent paths.
            - Identity Rotation: Randomizes User-Agent per request to bypass WAFs.
            - Fingerprinting: Captures MD5, Status, Size, Word Count, and Title.
            - Statistical Consistency: Requires 80% similarity to establish a baseline.

        Args:
            verbose_level (int): Verbosity level. Level 3 shows rotated User-Agents.

        Returns:
            tuple: (is_wildcard: bool, base_hash: str, avg_size: int, base_status: int, redirect_loc: str).
        """
        metrics = []
        self.logger.process(f"Analyzing network DNA (10 Stress Tests):{RESET}")
        
        try:
            for i in range(1, 11):
                random_path = f"wildcard_{random.getrandbits(24)}"
                test_url = f"{self.target_url}/{random_path}"
                
                # Identity Rotation
                current_ua = random.choice(self.user_agents)
                
                try:
                    headers = {"User-Agent": current_ua}
                    r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                     allow_redirects=False, verify=False)
                    
                    c_hash = hashlib.md5(r.content).hexdigest()
                    size = len(r.content)
                    words = len(r.text.split())
                    title = self._extract_title(r.text)
                    loc = r.headers.get("Location", "")
                    
                    # Enhanced Debug Info (-vvv)
                    ua_info = f" | {CYAN}UA: {current_ua[:35]}...{RESET}" if verbose_level >= 3 else ""
                    
                    msg = (f"{GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
                           f"Status: {CYAN}{r.status_code}{RESET} | Size: {CYAN}{size}{RESET} | "
                           f"Words: {CYAN}{words}{RESET} | Title: {WHITE}{title}{RESET}{ua_info}")
                    
                    self.logger.info(f"  {msg}")
                    
                    metrics.append({
                        'size': size, 
                        'hash': c_hash, 
                        'status': r.status_code,
                        'words': words,
                        'title': title,
                        'location': loc
                    })
                except requests.exceptions.RequestException:
                    self.logger.error(f"DNA Test {i:02d} failed: Connection Error")
                    continue

            if not metrics:
                return False, None, 0, 0, None

            # --- STATISTICAL ANALYSIS ---
            status_codes = [m['status'] for m in metrics]
            s_counts = Counter(status_codes)
            m_status, s_count = s_counts.most_common(1)[0]
            
            if s_count >= 8:
                h_counts = Counter([m['hash'] for m in metrics])
                m_hash = h_counts.most_common(1)[0][0]
                
                l_counts = Counter([m['location'] for m in metrics])
                m_loc = l_counts.most_common(1)[0][0]
                
                avg_size = sum([m['size'] for m in metrics]) / len(metrics)
                
                if (m_status // 100) in {2, 3}:
                    self.logger.error(f"WILDCARD DETECTED (Common Status: {m_status}){RESET}")
                    return True, m_hash, int(avg_size), m_status, m_loc
                
                self.logger.success(f"Stable 404 DNA identified (Size: {int(avg_size)}).{RESET}\n")
                return True, m_hash, int(avg_size), m_status, m_loc
            
            self.logger.warn(f"Unstable DNA: Multiple response patterns detected.{RESET}\n")
            return False, None, 0, 0, None

        except KeyboardInterrupt:
            from aimenreco.utils.exceptions import UserAbortException
            raise UserAbortException()
        except Exception as e:
            self.logger.error(f"DNA Analysis Error: {e}")
            return False, None, 0, 0, None