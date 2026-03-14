import requests
import random
import json
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE
from aimenreco.utils.helpers import get_resource_path

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery via Certificate Transparency (CT) Logs.
    Optimized for stealth by using randomized User-Agents and shared resources.
    """

    def __init__(self, domain, logger):
        self.domain = domain
        self.logger = logger
        # Load shared User-Agents for stealthy requests
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
        ])

    def _load_json_resource(self, filename, fallback):
        """
        Loads JSON data from the package resources folder.
        Used for wordlists, user-agents, and fingerprinting data.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            # Fallback to default list if file is missing or corrupted
            return fallback

    def fetch_subdomains(self):
        """
        Queries crt.sh API to extract subdomains from SSL/TLS certificates.
        Includes a multi-stage cleaning process to ensure data integrity.
        """
        self.logger.info(f"\n{YELLOW}[*] Starting Passive Phase: Querying CT Logs for {self.domain}...{RESET}")
        
        # crt.sh endpoint with JSON output for programmatic parsing
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            # 40s timeout because crt.sh is notoriously slow or unstable under load
            response = requests.get(url, timeout=40, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    # Entries may contain multiple names separated by newlines
                    raw_names = entry['name_value'].lower().split('\n')
                    for name in raw_names:
                        # --- STAGE 3.2: ADVANCED CLEANING PIPELINE ---
                        
                        # 1. Basic formatting
                        clean_name = name.lower().strip()

                        # 2. Strip common network prefixes and wildcards
                        for prefix in ['*.', 'http://', 'https://', 'www.']:
                            clean_name = clean_name.replace(prefix, '')

                        # 3. Truncate at first non-hostname character (paths, ports, or parsing residues)
                        for char in ['/', ' ', ':', ',']:
                            clean_name = clean_name.split(char)[0]

                        # 4. Target Validation: Must end with domain and not be the root domain itself
                        if clean_name.endswith(self.domain) and clean_name != self.domain:
                            # Avoid adding empty results or malformed short strings
                            if len(clean_name) > len(self.domain):
                                subdomains.add(clean_name)
                
                # Convert set to sorted list for clean UI presentation
                found_list = sorted(list(subdomains))
                self.logger.info(f"{GREEN}[✓] Found {len(found_list)} unique subdomains passive-wise.{RESET}")

                if found_list:
                    # Display the visual tree only if Quiet Mode is disabled
                    if not self.logger.quiet:
                        for sub in found_list:
                            print(f"  {WHITE}└─ {sub}{RESET}")
                        
                    # Persistence: Save results to a local file for further auditing
                    filename = f"passive_{self.domain}.txt"
                    try:
                        with open(filename, "w") as f:
                            f.write("\n".join(found_list) + "\n")
                        self.logger.info(f"\n  {CYAN}[i] OSINT Results saved to: {filename}{RESET}")
                    except Exception as e:
                        self.logger.error(f"  {RED}[!] File Write Error: {e}{RESET}")

                return found_list
            
            else:
                self.logger.error(f"OSINT Error: API returned status {response.status_code}")
            
        except requests.exceptions.Timeout:
            self.logger.error(f"OSINT Timeout: crt.sh is under heavy load. Skipping passive phase...")
        except Exception as e:
            self.logger.error(f"Passive Module Error: {e}")
        
        return []