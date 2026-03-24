#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import json
import time
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE, PURPLE
from aimenreco.utils.helpers import get_resource_path
from aimenreco.core.whois_module import WhoisAnalyzer

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery and domain intelligence.
    
    This module identifies subdomains via Certificate Transparency (CT) Logs 
    and gathers domain metadata through WHOIS lookups. It implements identity 
    shuffling, Client-Hints simulation, and adaptive jitter to bypass 
    rate-limiting and WAF blocks (e.g., Error 808).
    """

    def __init__(self, domain, logger, output_file=None):
        """
        Initializes the PassiveScanner with target details and rotation resources.

        Args:
            domain (str): The target domain to investigate.
            logger (Logger): Logger instance for formatted terminal output.
            output_file (str, optional): Path to the report file for data persistence.
        """
        self.whois_data = {}
        clean_domain = domain.lower().strip()
        
        # Strip protocols and common prefixes for clean WHOIS/CT queries
        for prefix in ['http://', 'https://', 'www.']:
            if clean_domain.startswith(prefix):
                clean_domain = clean_domain.replace(prefix, '', 1)
        
        # Ensure we only have the FQDN (strip paths or ports)
        self.domain = clean_domain.split('/')[0].split(':')[0]
        self.logger = logger
        self.output_file = output_file
        
        # Load rotation resources from the centralized JSON
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ])

    def _load_json_resource(self, filename, fallback):
        """
        Internal helper to load JSON data from the package resources.

        Args:
            filename (str): Name of the resource file.
            fallback (list): Default list if the file is missing or corrupted.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def _get_random_identity(self):
        """
        Generates a randomized HTTP header set to mimic real browser traffic.
        Includes User-Agent rotation and Sec-CH-UA (Client Hints) simulation.
        Ensures consistency between OS keywords and the Platform header.
        """
        ua = random.choice(self.user_agents)
        langs = ["en-US,en;q=0.9", "es-ES,es;q=0.8,en;q=0.7", "en-GB,en;q=0.9"]
        
        # Heuristic to match Sec-CH-UA-Platform (Ordered from specific to general)
        if "iPhone" in ua or "iPad" in ua: 
            platform = "iOS"
        elif "Android" in ua: 
            platform = "Android"
        elif "Macintosh" in ua: 
            platform = "macOS"
        elif "X11" in ua or "Linux" in ua: 
            platform = "Linux"
        else:
            platform = "Windows"

        return {
            'User-Agent': ua,
            'Accept': 'application/json, text/html, application/xhtml+xml',
            'Accept-Language': random.choice(langs),
            'Sec-CH-UA-Platform': f'"{platform}"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Referer': 'https://crt.sh/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _run_whois_phase(self, verbose_level=0):
        """
        Executes WHOIS lookup and displays intelligence using the Logger's tree system.

        Args:
            verbose_level (int): Depth of information to display in terminal.
        """
        self.logger.info(f"{YELLOW}Gathering WHOIS intelligence for{RESET} {PURPLE}{self.domain}{RESET}...")
        
        analyzer = WhoisAnalyzer(self.domain, self.logger)
        data = analyzer.run()
        
        if not data:
            self.logger.warn("WHOIS data could not be retrieved. Skipping to CT Logs...\n")
            return None

        # Display Logic (Tree-structured)
        self.logger.tree("Registrar", data.get('registrar', 'N/A'), color=GREEN)
        self.logger.tree("Creation", data.get('creation_date', 'N/A'), color=CYAN)
        self.logger.tree("Expiration", data.get('expiration_date', 'N/A'), color=CYAN)
        
        if data.get('tech_info'):
            self.logger.tree("Tech Stack", data['tech_info'], color=YELLOW)

        if verbose_level >= 1:
            org = data.get('org') if data.get('org') else "REDACTED"
            self.logger.tree("Organization", org)
            if data.get('status'):
                status_str = ", ".join(data['status'][:2])
                self.logger.tree("Domain Status", status_str, color=CYAN)

        ns_list = data.get('name_servers', [])
        ns_str = ", ".join(ns_list[:3]) if ns_list else "N/A"
        self.logger.tree("NameServers", ns_str, is_last=True)
        self.logger.info("") 
        
        self.whois_data = data
        return data

    def fetch_subdomains(self, verbose_level=0):
        """
        Orchestrates the passive reconnaissance phase with robust identity rotation.
        Queries Certificate Transparency logs with anti-ban mechanisms.

        Args:
            verbose_level (int): Level of detail for the terminal output.
        """
        self._run_whois_phase(verbose_level=verbose_level)

        self.logger.info(f"{YELLOW}[*] Querying CT Logs (crt.sh) for {self.domain}...{RESET}")
        
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        max_retries = 4
        
        for attempt in range(max_retries):
            try:
                headers = self._get_random_identity()
                
                if attempt > 0:
                    wait_time = random.uniform(5.0, 12.0)
                    self.logger.warn(f"Anti-ban jitter: Sleeping {wait_time:.1f}s before retry {attempt}/{max_retries}...")
                    time.sleep(wait_time)

                response = requests.get(url, timeout=45, headers=headers)
                
                if response.status_code == 200:
                    try:
                        return self._process_data(response.json())
                    except (json.JSONDecodeError, ValueError):
                        self.logger.warn(f"Malformed data (Error 808/Timeout). Rotating identity...")
                        continue
                
                if response.status_code in [404, 502, 503, 504]:
                    self.logger.warn(f"crt.sh busy or restricted ({response.status_code}). Swapping headers...")
                    continue
                
                break

            except (requests.exceptions.RequestException, requests.exceptions.Timeout):
                if attempt == max_retries - 1:
                    self.logger.error("Passive Phase failed: Connectivity issues with CT Logs.")
        
        return []

    def _process_data(self, data):
        """
        Parses and cleans the raw JSON data received from CT logs.
        Handles wildcards, duplicates, and out-of-scope entries.

        Args:
            data (list): List of dictionaries containing certificate info.
        """
        subdomains = set()
        for entry in data:
            raw_names = entry.get('name_value', '').lower().split('\n')
            for name in raw_names:
                clean_name = name.lower().strip()
                if clean_name.startswith("*."): clean_name = clean_name[2:]
                
                for prefix in ['http://', 'https://', 'www.']:
                    if clean_name.startswith(prefix):
                        clean_name = clean_name.replace(prefix, '', 1)
                
                for char in ['/', ' ', ':', ',']:
                    clean_name = clean_name.split(char)[0]

                if clean_name.endswith(self.domain) and clean_name != self.domain:
                    if clean_name.endswith("." + self.domain):
                        subdomains.add(clean_name)
        
        found_list = sorted(list(subdomains))
        self.logger.info(f"{GREEN}[✓] Found {len(found_list)} unique passive subdomains.{RESET}")

        if found_list and not self.logger.quiet:
            for i, sub in enumerate(found_list):
                self.logger.tree("Sub", sub, is_last=(i == len(found_list) - 1))
        
        print("") 
        return found_list