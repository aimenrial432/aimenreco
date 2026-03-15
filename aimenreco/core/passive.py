import requests
import random
import json
import time
import sys
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE
from aimenreco.utils.helpers import get_resource_path

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery via Certificate Transparency (CT) Logs.
    Updated with Exponential Backoff for 503 errors and clean Exit Handling.
    """

    def __init__(self, domain, logger, output_file=None):
        self.domain = domain
        self.logger = logger
        self.output_file = output_file
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
        ])

    def _load_json_resource(self, filename, fallback):
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def fetch_subdomains(self):
        """
        Queries crt.sh API with retry logic and keyboard interrupt protection.
        """
        self.logger.info(f"\n{YELLOW}[*] Starting Passive Phase: Querying CT Logs for {self.domain}...{RESET}")
        
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                # Increased timeout to 50s for heavy domains
                response = requests.get(url, timeout=50, headers=headers)
                
                if response.status_code == 200:
                    return self._process_data(response.json())
                
                if 500 <= response.status_code < 600:
                    wait_time = (attempt + 1) * 10
                    self.logger.warn(f"crt.sh Server Error ({response.status_code}). Retrying in {wait_time}s... ({attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                
                self.logger.error(f"OSINT Error: API returned status {response.status_code}")
                break

            except requests.exceptions.Timeout:
                self.logger.error(f"OSINT Timeout: crt.sh is slow. Retry {attempt+1}/{max_retries}...")
                continue
            except KeyboardInterrupt:
                # Clean exit on Ctrl+C
                print(f"\n{RED}[!] Passive Scan interrupted by user. Skipping to next phase...{RESET}")
                return []
            except Exception as e:
                self.logger.error(f"Passive Module Error: {e}")
                break
        
        return []

    def _process_data(self, data):
        """
        Internal helper to clean, normalize subdomain data and handle persistence logic.
        """
        subdomains = set()
        for entry in data:
            raw_names = entry['name_value'].lower().split('\n')
            for name in raw_names:
                clean_name = name.lower().strip()
                for prefix in ['*.', 'http://', 'https://', 'www.']:
                    clean_name = clean_name.replace(prefix, '')
                
                for char in ['/', ' ', ':', ',']:
                    clean_name = clean_name.split(char)[0]

                if clean_name.endswith(self.domain) and len(clean_name) > len(self.domain):
                    subdomains.add(clean_name)
        
        found_list = sorted(list(subdomains))
        self.logger.info(f"{GREEN}[✓] Found {len(found_list)} unique subdomains passive-wise.{RESET}")

        if found_list:
            # Always print the tree unless quiet mode is on
            if not self.logger.quiet:
                for sub in found_list:
                    print(f"  {WHITE}└─ {sub}{RESET}")
            
            # --- PERSISTENCE LOGIC ---
            
            if not self.output_file:
                self.logger.info(f"\n{CYAN}[i] Output flag (-o) not active. Passive results will not be persisted.{RESET}")

        return found_list