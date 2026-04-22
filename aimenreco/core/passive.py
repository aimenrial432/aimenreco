#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import json
import time
from typing import List, Set, Dict, Any, Optional, Union

from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE, PURPLE, GREY
from aimenreco.ui.logger import Logger
from aimenreco.utils.helpers import get_resource_path
from aimenreco.core.whois_module import WhoisAnalyzer
from aimenreco.core.intel import TechAnalyzer

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery and domain intelligence.
    
    This module identifies subdomains via Certificate Transparency (CT) Logs and 
    third-party APIs, gathers WHOIS data, and fingerprints the technology stack. 
    It implements adaptive jitter and identity rotation to bypass rate-limiting.
    """

    def __init__(self, domain: str, logger: Logger, output_file: Optional[str] = None) -> None:
        """
        Initializes the PassiveScanner with target details and anti-detection resources.

        Args:
            domain (str): The target domain to investigate.
            logger (Logger): Logger instance for formatted terminal output.
            output_file (str, optional): Path to the report file.
        """
        self.whois_data: Dict[str, Any] = {}
        self.tech_stack: List[str] = []
        clean_domain: str = domain.lower().strip()
        
        # Domain normalization: remove protocols and paths
        for prefix in ['http://', 'https://', 'www.']:
            if clean_domain.startswith(prefix):
                clean_domain = clean_domain.replace(prefix, '', 1)
        
        self.domain: str = clean_domain.split('/')[0].split(':')[0]
        self.logger: Logger = logger
        self.output_file: Optional[str] = output_file
        
        # Load user agent resources for identity rotation
        self.user_agents: List[str] = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ])

    def _load_json_resource(self, filename: str, fallback: List[str]) -> List[str]:
        """
        Loads JSON data from the package resources folder.
        """
        path: str = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                data: List[str] = json.load(f)
                return data
        except Exception:
            return fallback

    def _get_random_identity(self, verbose_level: int = 0) -> Dict[str, str]:
        """
        Generates a randomized HTTP header set to mimic legitimate browser traffic.
        """
        ua: str = random.choice(self.user_agents)
        headers: Dict[str, str] = {
            'User-Agent': ua,
            'Accept': 'application/json, text/html, application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
            'DNT': '1',
            'Connection': 'keep-alive'
        }

        if verbose_level >= 3:
            self.logger.info(f"{GREY}[DEBUG] Passive Identity: {ua[:50]}...{RESET}")

        return headers

    def _run_tech_phase(self) -> None:
        """
        Executes technology stack fingerprinting using the Intel module.
        """
        target_url: str = f"http://{self.domain}"
        analyzer: TechAnalyzer = TechAnalyzer(self.logger)
        self.tech_stack = analyzer.run(target_url)
        
        if self.tech_stack:
            for i, tech in enumerate(self.tech_stack):
                is_last: bool = (i == len(self.tech_stack) - 1)
                self.logger.tree("Technology", tech, color=CYAN, is_last=is_last)
            print("") 

    def _run_whois_phase(self, verbose_level: int = 0) -> Optional[Dict[str, Any]]:
        """
        Retrieves WHOIS registration data and displays key intelligence fields.
        """
        self.logger.process(f"{YELLOW}Gathering WHOIS intelligence for{RESET} {PURPLE}{self.domain}{RESET}...")
        analyzer: WhoisAnalyzer = WhoisAnalyzer(self.domain, self.logger)
        data: Optional[Dict[str, Any]] = analyzer.run()
        
        if not data:
            self.logger.warn("WHOIS data could not be retrieved.\n")
            return None

        self.logger.tree("Registrar", data.get('registrar', 'N/A'), color=GREEN)
        self.logger.tree("Creation", str(data.get('creation_date', 'N/A')), color=CYAN)
        self.logger.tree("Expiration", str(data.get('expiration_date', 'N/A')), color=CYAN)
        
        if verbose_level >= 1:
            org: str = str(data.get('org')) if data.get('org') else "REDACTED"
            self.logger.tree("Organization", org)

        ns_list: List[str] = data.get('name_servers', [])
        ns_str: str = ", ".join(ns_list[:3]) if ns_list else "N/A"
        self.logger.tree("NameServers", ns_str, is_last=True)
        print("") 
        
        self.whois_data = data
        return data

    def fetch_subdomains(self, verbose_level: int = 0) -> List[str]:
        """
        Coordinates the passive discovery flow: WHOIS -> Tech -> CT Logs -> Fallback.
        """
        # 1. WHOIS (Administrative Context)
        self._run_whois_phase(verbose_level=verbose_level)

        # 2. Technology Fingerprinting
        self.logger.process(f"{YELLOW}Identifying technology stack for{RESET} {PURPLE}{self.domain}...{RESET}")
        self._run_tech_phase()

        all_subdomains: Set[str] = set()

        # 3. Discovery: Query crt.sh (Priority Source)
        self.logger.process(f"{YELLOW}Querying CT Logs (crt.sh) for{RESET} {PURPLE}{self.domain}...{RESET}")
        ct_results: Set[str] = self._query_crtsh(verbose_level)
        all_subdomains.update(ct_results)

        # 4. Fallback: Query HackerTarget if CT logs returned no results
        if not all_subdomains:
            self.logger.warn(f"{YELLOW}CT Logs exhausted with no results. Trying HackerTarget...{RESET}")
            ht_results: List[str] = self._query_hackertarget(verbose_level)
            all_subdomains.update(ht_results)

        found_list: List[str] = sorted(list(all_subdomains))
        self.logger.success(f"{GREEN}Found {len(found_list)} unique passive subdomains.{RESET}")

        if found_list and not self.logger.quiet:
            for i, sub in enumerate(found_list):
                self.logger.tree("Sub", sub, is_last=(i == len(found_list) - 1))
        
        print("") 
        return found_list

    def _query_crtsh(self, verbose_level: int) -> Set[str]:
        """
        Queries crt.sh with identity rotation and adaptive jitter.
        """
        url: str = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        for attempt in range(4):
            try:
                headers: Dict[str, str] = self._get_random_identity(verbose_level=verbose_level)
                
                if attempt > 0:
                    wait_time: float = random.uniform(5.0, 10.0)
                    self.logger.warn(f"Anti-ban jitter: Sleeping {wait_time:.1f}s (Retry {attempt}/4)...")
                    time.sleep(wait_time)

                response = requests.get(url, headers=headers, timeout=35)
                
                if response.status_code == 200:
                    return self._parse_raw_data(response.json(), 'name_value')
                
                if response.status_code in [502, 503, 429]:
                    self.logger.warn(f"crt.sh busy/restricted ({response.status_code}). Swapping identity...")
                    continue
            except Exception as e:
                if verbose_level >= 3:
                    self.logger.info(f"{GREY}[DEBUG] Connection error: {str(e)}{RESET}")
                continue
                
        return set()

    def _query_hackertarget(self, verbose_level: int) -> List[str]:
        """
        Secondary discovery source via HackerTarget's hostsearch API.
        """
        if verbose_level >= 2:
            self.logger.info(f"{GREY}[DEBUG] Contacting HackerTarget API...{RESET}")
        
        url: str = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200 and "error" not in r.text:
                return [line.split(',')[0] for line in r.text.split('\n') if line]
        except Exception:
            pass
        return []

    def _parse_raw_data(self, data: List[Any], key: str) -> Set[str]:
        """
        Normalizes and filters subdomain strings extracted from JSON responses.
        """
        extracted: Set[str] = set()
        for entry in data:
            raw_value: str = entry.get(key, '') if isinstance(entry, dict) else str(entry)
            for name in str(raw_value).lower().split('\n'):
                clean: str = name.strip().replace('*.', '')
                if clean.endswith(self.domain) and clean != self.domain:
                    if clean.endswith("." + self.domain):
                        extracted.add(clean)
        return extracted