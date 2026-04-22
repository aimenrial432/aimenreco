#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
import random
import hashlib
import json
from typing import List, Tuple, Dict, Any, Optional
from collections import Counter

from aimenreco.ui.colors import YELLOW, GREY, WHITE, CYAN, RED, RESET, GREEN
from aimenreco.ui.logger import Logger
from aimenreco.utils.helpers import get_resource_path
from aimenreco.models import WildcardDNA

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

    def __init__(self, target_url: str, logger: Logger, timeout: float = 5.0) -> None:
        """
        Initializes the analyzer with target connection parameters and logger.

        Args:
            target_url (str): Target base URL.
            logger (Logger): Centralized logging instance.
            timeout (float): Seconds to wait for server response.
        """
        self.target_url: str = target_url
        self.logger: Logger = logger
        self.timeout: float = timeout
        self.user_agents: List[str] = self._load_json_resource("user_agents.json", ["Aimenreco/3.2"])

    def _load_json_resource(self, filename: str, fallback: List[str]) -> List[str]:
        """
        Internal helper to load JSON data from package resources.

        Args:
            filename (str): Name of the resource file.
            fallback (list): Default list if file is missing.
        """
        path: str = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                data: List[str] = json.load(f)
                return data
        except Exception:
            return fallback

    def _extract_title(self, html: str) -> str:
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

    def check(self, verbose_level: int = 0) -> Tuple[bool, Optional[str], int, int, Optional[str]]:
        """
        Executes a 10-point DNA stress test to identify stability and wildcards.

        Returns:
            tuple: (is_wildcard: bool, base_hash: str, avg_size: int, base_status: int, redirect_loc: str).
        """
        metrics: List[Dict[str, Any]] = []
        self.logger.process(f"Analyzing network DNA (10 Stress Tests):{RESET}")
        
        try:
            for i in range(1, 11):
                random_path: str = f"wildcard_{random.getrandbits(24)}"
                test_url: str = f"{self.target_url}/{random_path}"
                
                # Identity Rotation
                current_ua: str = random.choice(self.user_agents)
                
                try:
                    headers: Dict[str, str] = {"User-Agent": current_ua}
                    r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                     allow_redirects=False, verify=False)
                    
                    c_hash: str = hashlib.md5(r.content).hexdigest()
                    size: int = len(r.content)
                    words: int = len(r.text.split())
                    title: str = self._extract_title(r.text)
                    loc: str = r.headers.get("Location", "")
                    
                    # Enhanced Debug Info (-vvv)
                    ua_info: str = f" | {CYAN}UA: {current_ua[:35]}...{RESET}" if verbose_level >= 3 else ""
                    
                    msg: str = (f"{GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
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
            status_codes: List[int] = [m['status'] for m in metrics]
            s_counts = Counter(status_codes)
            m_status, s_count = s_counts.most_common(1)[0]
            
            if s_count >= 8:
                h_counts = Counter([m['hash'] for m in metrics])
                m_hash: str = h_counts.most_common(1)[0][0]
                
                l_counts = Counter([m['location'] for m in metrics])
                m_loc: str = l_counts.most_common(1)[0][0]
                
                avg_size: float = sum([m['size'] for m in metrics]) / len(metrics)
                
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