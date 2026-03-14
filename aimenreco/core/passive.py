import requests
import random
import json
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN, WHITE
from aimenreco.utils.helpers import get_resource_path

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery via CT Logs.
    Uses shared resources for stealth and consistency.
    """

    def __init__(self, domain):
        self.domain = domain
        # Load shared User-Agents for stealth
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
        ])

    def _load_json_resource(self, filename, fallback):
        """Loads JSON data from the package resources folder."""
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except:
            return fallback

    def fetch_subdomains(self):
        print(f"\n{YELLOW}[*] Starting Passive Phase: Querying CT Logs for {self.domain}...{RESET}")
        
        # El endpoint de crt.sh con salida JSON
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(url, timeout=40, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    raw_names = entry['name_value'].lower().split('\n')
                    for name in raw_names:
                        # --- LIMPIEZA AVANZADA ---
                        # Eliminamos wildcards, protocolos y posibles rutas
                        clean_name = name.replace('*.', '').replace('http://', '').replace('https://', '')
                        clean_name = clean_name.split('/')[0].strip()
                        
                        # Validamos que termine en nuestro dominio y no sea solo el dominio raíz
                        if clean_name.endswith(self.domain) and clean_name != self.domain:
                            subdomains.add(clean_name)
                
                found_list = sorted(list(subdomains))
                print(f"{GREEN}[✓] Found {len(found_list)} unique subdomains passive-wise.{RESET}")

                if found_list:
                    # Imprimimos los resultados con estilo de árbol
                    for sub in found_list:
                        print(f"  {WHITE}└─ {sub}{RESET}")
                        
                    filename = f"passive_{self.domain}.txt"
                    try:
                        with open(filename, "w") as f:
                            f.write("\n".join(found_list) + "\n")
                        print(f"\n  {CYAN}[i] OSINT Results saved to: {filename}{RESET}")
                    except Exception as e:
                        print(f"  {RED}[!] Write Error: {e}{RESET}")

                return found_list
            
            else:
                print(f"{RED}[!] OSINT Error: API returned status {response.status_code}{RESET}")
            
        except requests.exceptions.Timeout:
            print(f"{RED}[!] OSINT Timeout: crt.sh is under heavy load. Skipping passive phase...{RESET}")
        except Exception as e:
            print(f"{RED}[!] Passive Module Error: {e}{RESET}")
        
        return []