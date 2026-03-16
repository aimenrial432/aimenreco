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
    
    This module identifies subdomains by querying public CT log agregators like crt.sh,
    allowing for discovery without direct interaction with the target infrastructure.
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
            clean_domain = clean_domain.replace(prefix, '')
            
        self.domain = clean_domain.split('/')[0]
        self.logger = logger
        self.output_file = output_file
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
        ])

    def _load_json_resource(self, filename, fallback):
        """
        Internal helper to load JSON data from the package resources.
        
        Args:
            filename (str): Name of the JSON file to load.
            fallback (list/dict): Default value if the file is missing or corrupt.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def fetch_subdomains(self):
        """
        Queries the crt.sh API to retrieve subdomain records.
        
        Implements exponential backoff for 5xx errors and network timeouts.
        Does not catch UserAbortException to allow graceful CLI interruption.

        Returns:
            list: A sorted list of unique subdomains found.
        """
        self.logger.info(f"\n{YELLOW}[*] Starting Passive Phase: Querying CT Logs for {self.domain}...{RESET}")
        
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                # Increased timeout to handle large database queries on crt.sh
                response = requests.get(url, timeout=50, headers=headers)
                
                if response.status_code == 200:
                    try:
                        return self._process_data(response.json())
                    except (json.JSONDecodeError, ValueError):
                        self.logger.error("Failed to parse OSINT data: Invalid JSON response.")
                        return []
                
                # Retry on server-side errors (500, 502, 503, 504)
                if 500 <= response.status_code < 600:
                    wait_time = (attempt + 1) * 10
                    self.logger.warn(f"crt.sh server busy ({response.status_code}). Retrying in {wait_time}s... ({attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                
                # Handle potential blocking or invalid requests
                self.logger.error(f"OSINT Error: API returned status {response.status_code}")
                break

            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                # Catch network-level issues to allow retries
                self.logger.debug(f"Connection attempt {attempt+1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    self.logger.error(f"Passive Phase failed: Connectivity issues with crt.sh.")
        
        return []

    def _process_data(self, data):
        """
        Cleans and normalizes the raw data received from CT logs.
        
        Args:
            data (list): Raw JSON records from crt.sh.
            
        Returns:
            list: deduplicated and formatted subdomain strings.
        """
        subdomains = set()
        for entry in data:
            # Entry names often contain multiple domains separated by newlines
            raw_names = entry.get('name_value', '').lower().split('\n')
            for name in raw_names:
                clean_name = name.lower().strip()
                
                # Strip wildcards and protocol schemes
                for prefix in ['*.', 'http://', 'https://', 'www.']:
                    clean_name = clean_name.replace(prefix, '')
                
                # Filter out paths or port numbers often found in SAN certificates
                for char in ['/', ' ', ':', ',']:
                    clean_name = clean_name.split(char)[0]

                # Ensure the subdomain belongs to the target and isn't the root domain
                if clean_name.endswith(self.domain) and len(clean_name) > len(self.domain):
                    subdomains.add(clean_name)
        
        found_list = sorted(list(subdomains))
        self.logger.info(f"{GREEN}[✓] Found {len(found_list)} unique subdomains passive-wise.{RESET}")

        if found_list:
            if not self.logger.quiet:
                for sub in found_list:
                    print(f"  {WHITE}└─ {sub}{RESET}")
            
            if not self.output_file:
                self.logger.info(f"\n{CYAN}[i] Output flag (-o) not active. Passive results will not be persisted.{RESET}")

        return found_list