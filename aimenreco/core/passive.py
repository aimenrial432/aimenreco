import requests
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED, CYAN

class PassiveScanner:
    """
    Passive reconnaissance engine for subdomain discovery.

    This module leverages Certificate Transparency (CT) logs via the crt.sh API 
    to identify subdomains associated with a target domain. This method is 
    non-intrusive (OSINT) as it does not interact directly with the target's 
    infrastructure.

    Attributes:
        domain (str): The root domain to investigate (e.g., 'example.com').
    """

    def __init__(self, domain):
        """
        Initializes the PassiveScanner with a target domain.

        Args:
            domain (str): The target domain for OSINT analysis.
        """
        self.domain = domain

    def fetch_subdomains(self):
        """
        Queries crt.sh to extract subdomains from SSL/TLS certificates.

        The process involves:
        1. Querying crt.sh with a wildcard pattern (%.domain.com).
        2. Parsing JSON response for 'name_value' fields.
        3. Sanitizing output (lowercasing, removing wildcards, filtering duplicates).
        4. Persisting results to a local text file.

        Returns:
            list: A sorted list of unique subdomains found.
        """
        print(f"\n{YELLOW}[*] Starting Passive Phase: Querying SSL certificates for {self.domain}...{RESET}")
        
        # crt.sh API endpoint for JSON output
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        try:
            # Added a standard User-Agent to avoid potential API blocks
            headers = {'User-Agent': 'Aimenreco/3.0'}
            response = requests.get(url, timeout=40, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()  # Using a set to ensure uniqueness
                
                for entry in data:
                    # name_value may contain multiple subdomains separated by newlines
                    name = entry['name_value'].lower()
                    for sub in name.split('\n'):
                        # Filter: must end with target domain and exclude wildcard notations
                        if sub.endswith(self.domain) and "*" not in sub:
                            subdomains.add(sub)
                
                found_list = sorted(list(subdomains))
                print(f"{GREEN}[✓] Found {len(found_list)} unique subdomains.{RESET}")

                # Automatic Persistence Logic
                if found_list:
                    filename = f"subdomains_{self.domain}.txt"
                    try:
                        with open(filename, "w") as f:
                            f.write("\n".join(found_list) + "\n")
                        print(f"  {CYAN}[i] Persistence: Targets saved to {filename}{RESET}")
                    except Exception as e:
                        print(f"  {RED}[!] File Write Error: {e}{RESET}")

                return found_list
            else:
                print(f"{RED}[!] API Error: Received status code {response.status_code}{RESET}")
            
        except requests.exceptions.Timeout:
            print(f"{RED}[!] Error: crt.sh API timed out (server might be overloaded).{RESET}")
        except Exception as e:
            print(f"{RED}[!] Passive Module Exception: {e}{RESET}")
        
        return []