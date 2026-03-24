#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from aimenreco.ui.colors import CYAN, RED, RESET, GREEN, WHITE

class Reporter:
    """
    Handles the persistence of scan results to the file system.
    
    This class centralizes all write operations, ensuring consistent 
    formatting for passive OSINT intelligence, active scanning results,
    and metadata reports.
    """
    def __init__(self, output_path, logger=None):
        """
        Initializes the Reporter with a destination path.
        
        :param output_path: String path to the output file.
        :param logger: Optional Logger instance for status reporting.
        """
        self.output_path = output_path
        self.logger = logger
        
        if self.output_path:
            self._initialize_report()

    def _initialize_report(self):
        """
        Creates the file and writes the global header if it doesn't exist.
        """
        if not os.path.exists(self.output_path):
            try:
                with open(self.output_path, "w", encoding="utf-8") as f:
                    f.write(f"{'='*60}\n")
                    f.write(f" AIMENRECO DISCOVERY REPORT\n")
                    f.write(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*60}\n\n")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to initialize report file: {e}")

    def write_intelligence(self, domain, data):
        """
        Persists WHOIS and domain intelligence metadata to the output file.

        :param domain: The target domain string.
        :param data: Dictionary containing WHOIS/technical data.
        """
        if not self.output_path or not data:
            return

        try:
            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(f"\n[+] DOMAIN INTELLIGENCE: {domain}\n")
                f.write(f"{'-'*60}\n")
                f.write(f"Registrar:    {data.get('registrar', 'N/A')}\n")
                f.write(f"Creation:     {data.get('creation_date', 'N/A')}\n")
                f.write(f"Expiration:   {data.get('expiration_date', 'N/A')}\n")
                f.write(f"Organization: {data.get('org', 'REDACTED')}\n")
                
                ns = data.get('name_servers', [])
                f.write(f"NameServers:  {', '.join(ns) if ns else 'N/A'}\n")
                
                if data.get('tech_info'):
                    f.write(f"Tech Stack:   {data.get('tech_info')}\n")
                
                f.write(f"{'-'*60}\n")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write intelligence data: {e}")

    def write_section(self, title, results):
        """
        Writes a formatted section of results (e.g., subdomains) to the output file.
        
        :param title: The header title for the section (e.g., 'Passive Recon').
        :param results: List of strings containing the findings.
        """
        if not self.output_path or not results:
            return

        try:
            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*20} {title.upper()} {'='*20}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
                for item in results:
                    f.write(f"{item}\n")
                f.write(f"\n[!] Total items in section: {len(results)}\n")
                f.write("-" * 50 + "\n")
            
            if self.logger:
                self.logger.info(f"{CYAN}[i] Results for '{title}' saved to {WHITE}{self.output_path}{RESET}.")
        except Exception as e:
            if self.logger:
                self.logger.error(f"{RED}[!] Failed to write to {self.output_path}: {e}{RESET}")