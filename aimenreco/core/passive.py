import requests
from aimenreco.ui.colors import GREEN, RESET, YELLOW, RED

class PassiveScanner:
    def __init__(self, domain):
        self.domain = domain

    def fetch_subdomains(self):
        """Consulta la base de datos de crt.sh para encontrar subdominios"""
        print(f"\n{YELLOW}[*] Iniciando Fase Pasiva: Consultando certificados SSL para {self.domain}...{RESET}")
        
        # crt.sh es una base de datos pública de certificados
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        try:
            response = requests.get(url, timeout=40)
            if response.status_code == 200:
                data = response.json()
                subdomains = set() # Usamos set para evitar duplicados automáticos
                
                for entry in data:
                    name = entry['name_value'].lower()
                    # A veces vienen varios en una línea separados por \n
                    for sub in name.split('\n'):
                        if sub.endswith(self.domain) and "*" not in sub:
                            subdomains.add(sub)
                
                found_list = sorted(list(subdomains))
                print(f"{GREEN}[✓] Se han encontrado {len(found_list)} subdominios únicos.{RESET}")
                return found_list
            
        except Exception as e:
            print(f"{RED}[!] Error en el módulo pasivo: {e}{RESET}")
        
        return []