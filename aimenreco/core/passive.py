#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import json
import time
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE, PURPLE
from aimenreco.utils.helpers import get_resource_path
# Import the new WHOIS module
from aimenreco.core.whois_module import WhoisAnalyzer

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery and domain intelligence.
    
    This module identifies subdomains via Certificate Transparency (CT) Logs 
    and gathers domain metadata through WHOIS lookups.
    """

    def __init__(self, domain, logger, output_file=None):
        """
        Initializes the PassiveScanner with target details and logging.

        Args:
            domain (str): The target domain to investigate.
            logger (Logger): Logger instance for formatted terminal output.
            output_file (str, optional): Path to the report file for data persistence.
        """
        clean_domain = domain.lower().strip()
        
        for prefix in ['http://', 'https://', 'www.']:
            if clean_domain.startswith(prefix):
                clean_domain = clean_domain.replace(prefix, '', 1)
        
        clean_domain = clean_domain.split('/')[0].split(':')[0]
            
        self.domain = clean_domain
        self.logger = logger
        self.output_file = output_file
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
        ])

    def _load_json_resource(self, filename, fallback):
        """
        Internal helper to load JSON data from the package resources.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def _run_whois_phase(self):
        """
        Executes WHOIS lookup and displays formatted intelligence.
        """
        # Header for the sub-section
        self.logger.info(f"{YELLOW}Gathering WHOIS intelligence for{RESET} {PURPLE}{self.domain}{RESET}...")
        
        analyzer = WhoisAnalyzer(self.domain, self.logger)
        data = analyzer.run()
        
        if data:
            # All lines now use a consistent sub-tree style
            print(f"   {PURPLE}├─{RESET} {WHITE}Registrar:{RESET} {GREEN}{data['registrar']}{RESET}")
            print(f"   {PURPLE}├─{RESET} {WHITE}Creation:{RESET}  {CYAN}{data['creation_date']}{RESET}")
            
            # Show Infrastructure info if detected
            if data['tech_info']:
                print(f"   {PURPLE}├─{RESET} {WHITE}Tech Stack:{RESET} {YELLOW}{data['tech_info']}{RESET}")

            ns_str = ", ".join(data['name_servers'][:2]) # Top 2 NS
            print(f"   {PURPLE}├─{RESET} {WHITE}NameServers:{RESET} {ns_str}")
            
            email_str = ", ".join(data['emails'][:1]) if data['emails'] else "N/A"
            print(f"   {PURPLE}└─{RESET} {WHITE}Contact:{RESET} {email_str}")
            print("") # Extra line for readability
        else:
            self.logger.warn("WHOIS data could not be retrieved. \n")
        
        return data

    def fetch_subdomains(self):
        """
        Main execution flow for the passive phase.
        
        It first performs a WHOIS lookup and then queries the crt.sh API 
        to retrieve subdomain records.

        Returns:
            list: A sorted list of unique subdomains found.
        """
        # --- NEW: WHOIS PHASE ---
        self._run_whois_phase()

        # --- CT LOGS PHASE ---
        self.logger.info(f"{YELLOW}[*] Starting Passive Phase: Querying CT Logs for {self.domain}...{RESET}")
        
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = requests.get(url, timeout=50, headers=headers)
                
                if response.status_code == 200:
                    try:
                        return self._process_data(response.json())
                    except (json.JSONDecodeError, ValueError):
                        self.logger.error("Failed to parse OSINT data: Invalid JSON response.")
                        return []
                
                if 500 <= response.status_code < 600:
                    wait_time = (attempt + 1) * 10
                    self.logger.warn(f"crt.sh server busy ({response.status_code}). Retrying in {wait_time}s... ({attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                
                self.logger.error(f"OSINT Error: API returned status {response.status_code}")
                break

            except (requests.exceptions.RequestException, requests.exceptions.Timeout):
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    self.logger.error(f"Passive Phase failed: Connectivity issues with crt.sh.")
        
        return []

    def _process_data(self, data):
        """
        Cleans and normalizes the raw data received from CT logs.
        """
        subdomains = set()
        for entry in data:
            raw_names = entry.get('name_value', '').lower().split('\n')
            for name in raw_names:
                clean_name = name.lower().strip()
                
                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]
                
                for prefix in ['http://', 'https://', 'www.']:
                    if clean_name.startswith(prefix):
                        clean_name = clean_name.replace(prefix, '', 1)
                
                for char in ['/', ' ', ':', ',']:
                    clean_name = clean_name.split(char)[0]

                if clean_name.endswith(self.domain):
                    if clean_name == self.domain:
                        continue 
                    
                    if clean_name.endswith("." + self.domain):
                        subdomains.add(clean_name)
        
        found_list = sorted(list(subdomains))
        self.logger.info(f"{GREEN}[✓] Found {len(found_list)} unique subdomains passive-wise.{RESET}")

        if found_list and not self.logger.quiet:
            for sub in found_list:
                print(f"  {WHITE}└─ {sub}{RESET}")

        return found_list