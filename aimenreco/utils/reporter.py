#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

from aimenreco.ui.colors import CYAN, RED, RESET, GREEN, WHITE
from aimenreco.ui.logger import Logger

class Reporter:
    """
    Handles the persistence of scan results to the file system.
    
    This class centralizes all write operations, ensuring consistent 
    formatting for passive OSINT intelligence, active scanning results,
    and metadata reports.
    """
    
    def __init__(self, output_path: Optional[str], logger: Optional[Logger] = None) -> None:
        """
        Initializes the Reporter with a destination path.
        
        Args:
            output_path: Optional string path to the output file.
            logger: Optional Logger instance for status reporting.
        """
        self.output_path: Optional[str] = output_path
        self.logger: Optional[Logger] = logger
        
        if self.output_path:
            self._initialize_report()

    def _initialize_report(self) -> None:
        """
        Creates the file and writes the global header if it doesn't exist.
        """
        if self.output_path and not os.path.exists(self.output_path):
            try:
                with open(self.output_path, "w", encoding="utf-8") as f:
                    f.write(f"{'='*60}\n")
                    f.write(f" AIMENRECO DISCOVERY REPORT\n")
                    f.write(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*60}\n\n")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to initialize report file: {e}")

    def write_intelligence(self, domain: str, data: Dict[str, Any]) -> None:
        """
        Persists WHOIS and domain intelligence metadata to the output file.

        Args:
            domain: The target domain string.
            data: Dictionary containing WHOIS/technical data.
        """
        if not self.output_path or not data:
            return

        try:
            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(f"\n[+] DOMAIN INTELLIGENCE: {domain}\n")
                f.write(f"{'-'*60}\n")
                f.write(f"Registrar:     {data.get('registrar', 'N/A')}\n")
                f.write(f"Creation:      {data.get('creation_date', 'N/A')}\n")
                f.write(f"Expiration:    {data.get('expiration_date', 'N/A')}\n")
                f.write(f"Organization:  {data.get('org', 'REDACTED')}\n")
                
                ns: List[str] = data.get('name_servers', [])
                f.write(f"NameServers:   {', '.join(ns) if ns else 'N/A'}\n")
                
                # Tech info can still be written here if part of data dict
                tech: Optional[str] = data.get('tech_info')
                if tech:
                    f.write(f"Tech Stack:    {tech}\n")
                
                f.write(f"{'-'*60}\n")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write intelligence data: {e}")

    def write_section(self, title: str, results: List[Any]) -> None:
        """
        Writes a formatted section of results (e.g., subdomains, technologies) 
        to the output file.
        
        Args:
            title: The header title for the section (e.g., 'Passive Subdomains').
            results: List of findings to persist.
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
                f.write(f"\n[✓] Total items in section: {len(results)}\n")
                f.write("-" * 50 + "\n")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"{RED}[!] Failed to write to {self.output_path}: {e}{RESET}")