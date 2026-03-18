#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import whois
import datetime
import time
import random
from aimenreco.ui.colors import PURPLE, RESET, CYAN, WHITE, YELLOW
# Import your custom exception to ensure global abort
from aimenreco.utils.exceptions import UserAbortException

class WhoisAnalyzer:
    """
    Domain information extractor using WHOIS protocols with retry logic.
    
    This module retrieves registration details, nameservers, and ownership data.
    It implements a retry mechanism with exponential backoff to handle 
    connection resets or rate-limits often imposed by WHOIS servers.
    """

    def __init__(self, domain, logger):
        """
        Initializes the WhoisAnalyzer.

        Args:
            domain (str): The target domain to query.
            logger (Logger): Logger instance for formatted output.
        """
        self.domain = domain
        self.logger = logger
        self.results = {}

    def run(self):
        """
        Executes the WHOIS query with a retry mechanism.
        
        Returns:
            dict: Processed WHOIS data or None if all attempts fail.
        """
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # Actual WHOIS query
                raw_data = whois.whois(self.domain)
                
                if not raw_data or not raw_data.domain_name:
                    if attempt < max_retries - 1:
                        raise ValueError("Empty WHOIS response")
                    return None

                # Parsing and standardizing fields
                self.results = {
                    "registrar": self._ensure_string(raw_data.registrar),
                    "org": self._ensure_string(raw_data.org) or "REDACTED FOR PRIVACY",
                    "creation_date": self._format_date(raw_data.creation_date),
                    "expiration_date": self._format_date(raw_data.expiration_date),
                    "name_servers": self._format_nameservers(raw_data.name_servers),
                    "emails": self._ensure_list(raw_data.emails),
                    "tech_info": self._detect_infrastructure(raw_data.name_servers)
                }
                
                return self.results
            
            except (KeyboardInterrupt, UserAbortException):
                # Crucial: Raise UserAbortException to let the CLI handle the exit
                raise UserAbortException()

            except Exception:
                # Genetic exceptions trigger the retry logic
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2 + random.random()
                    self.logger.info(f"{YELLOW}[!] WHOIS lookup failed. Retrying in {wait_time:.1f}s... ({attempt + 1}/{max_retries}){RESET}")
                    time.sleep(wait_time)
                else:
                    # Silent failure on the last attempt
                    return None

    def _ensure_string(self, data):
        """Converts list-based WHOIS responses into a single string."""
        if isinstance(data, list):
            return str(data[0]) if data else ""
        return str(data) if data else ""

    def _ensure_list(self, data):
        """Ensures the data is returned as a list of strings."""
        if not data:
            return []
        if isinstance(data, list):
            return [str(i).lower() for i in data if i]
        return [str(data).lower()]

    def _format_date(self, d):
        """Standardizes date objects to YYYY-MM-DD format."""
        if not d:
            return "N/A"
        target_date = d[0] if isinstance(d, list) else d
        if isinstance(target_date, datetime.datetime):
            return target_date.strftime("%Y-%m-%d")
        return str(target_date).split()[0]

    def _format_nameservers(self, ns):
        """Cleans and normalizes Name Server strings."""
        raw_list = self._ensure_list(ns)
        return sorted(list(set([n.lower() for n in raw_list])))

    def _detect_infrastructure(self, ns):
        """Identifies third-party infrastructure (WAF/Cloud) based on NS."""
        ns_str = str(ns).lower()
        if "cloudflare" in ns_str:
            return "Cloudflare WAF Detected"
        if "awsdns" in ns_str:
            return "Amazon AWS Infrastructure"
        if "googledomains" in ns_str:
            return "Google Cloud Infrastructure"
        return None
    