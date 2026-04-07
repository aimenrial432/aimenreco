import subprocess
import json
import shutil
import requests
import hashlib
from aimenreco.ui.colors import GREY, RESET, CYAN, YELLOW
from aimenreco.utils.helpers import get_resource_path

class TechAnalyzer:
    """
    Advanced Technology Fingerprinting Engine.
    
    Orchestrates specialized discovery modules including WhatWeb binary 
    execution, HTTP header analysis, and Favicon MD5 hash matching.
    """
    def __init__(self, logger):
        """
        Initializes the TechAnalyzer and loads external signature resources.
        """
        self.logger = logger
        self.favicon_db = self._load_signatures("favicons.json")

    def _load_signatures(self, filename):
        """
        Loads technology signatures from JSON resources.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def get_favicon_hash(self, url):
        """
        Retrieves the favicon.ico and matches its MD5 against the signature DB.
        """
        try:
            icon_url = f"{url.rstrip('/')}/favicon.ico"
            # Use a generic UA for the request to avoid simple blocks
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(icon_url, timeout=5, verify=False, headers=headers)
            
            if response.status_code == 200:
                md5 = hashlib.md5(response.content).hexdigest()
                cms = self.favicon_db.get(md5)
                if cms:
                    return [f"CMS: {cms} (via Favicon)"]
        except Exception:
            pass
        return []

    def get_whatweb(self, url):
        """
        Executes WhatWeb CLI with JSON logging to extract technology metadata.
        """
        if not shutil.which("whatweb"):
            return []
        try:
            result = subprocess.run(
                ["whatweb", url, "--log-json=/dev/stdout", "-q"],
                capture_output=True, text=True, timeout=15
            )
            data = json.loads(result.stdout)
            if data and "plugins" in data[0]:
                return [f"{p} ({v['version'][0]})" if v.get("version") else p 
                        for p, v in data[0]["plugins"].items()]
        except Exception:
            pass
        return []

    def get_headers_tech(self, url):
        """
        Parses raw HTTP response headers for technology disclosure.
        """
        try:
            r = requests.get(url, timeout=5, verify=False)
            techs = []
            server = r.headers.get("Server")
            powered = r.headers.get("X-Powered-By")
            if server: techs.append(f"Server: {server}")
            if powered: techs.append(f"Powered-By: {powered}")
            return techs
        except Exception:
            return []

    def run(self, url):
        """
        Main entry point for technology identification.
        """
        
        results = set()
        results.update(self.get_whatweb(url))
        results.update(self.get_headers_tech(url))
        results.update(self.get_favicon_hash(url))
        
        return sorted(list(filter(None, results)))