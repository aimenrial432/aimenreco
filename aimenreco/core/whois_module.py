#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import whois
import datetime
import time
import random
from typing import List, Dict, Any, Optional, Union

from aimenreco.ui.colors import PURPLE, RESET, CYAN, WHITE, YELLOW
from aimenreco.ui.logger import Logger
from aimenreco.utils.exceptions import UserAbortException

class WhoisAnalyzer:
    """
    Advanced Domain Intelligence extractor using WHOIS protocols.
    
    This module retrieves registration details, nameservers, and security
    metadata (DNSSEC, EPP status). It implements a retry mechanism with 
    exponential backoff to bypass rate-limiting on public WHOIS servers.
    """

    def __init__(self, domain: str, logger: Logger) -> None:
        """
        Initializes the WhoisAnalyzer.

        Args:
            domain (str): The target domain to query.
            logger (Logger): Logger instance for formatted output.
        """
        self.domain: str = domain
        self.logger: Logger = logger
        self.results: Dict[str, Any] = {}

    def run(self) -> Optional[Dict[str, Any]]:
        """
        Executes the WHOIS query with a retry mechanism and global abort support.
        
        Returns:
            dict: Processed WHOIS data containing basic and advanced fields.
                  Returns None if all retry attempts fail.
        """
        max_retries: int = 3
        
        for attempt in range(max_retries):
            try:
                # Perform the actual WHOIS lookup
                raw_data: Any = whois.whois(self.domain)
                
                if not raw_data or not raw_data.domain_name:
                    if attempt < max_retries - 1:
                        raise ValueError("Empty WHOIS response")
                    return None

                # DATA EXTRACTION: Capturing fields for all verbosity levels
                self.results = {
                    # Basic Level (Standard output)
                    "registrar": self._ensure_string(raw_data.registrar),
                    "creation_date": self._format_date(raw_data.creation_date),
                    "expiration_date": self._format_date(raw_data.expiration_date),
                    "name_servers": self._format_nameservers(raw_data.name_servers),
                    
                    # Verbose Level (-v)
                    "org": self._ensure_string(raw_data.org) or "REDACTED",
                    "status": self._format_status(raw_data.status),
                    "dnssec": self._ensure_string(raw_data.dnssec),
                    "emails": self._ensure_list(raw_data.emails),
                    
                    # Debug Level (-vv / -vvv)
                    "updated_date": self._format_date(raw_data.updated_date),
                    "whois_server": self._ensure_string(raw_data.whois_server),
                    "country": self._ensure_string(raw_data.country),
                    "city": self._ensure_string(raw_data.city),
                    "tech_info": self._detect_infrastructure(raw_data.name_servers)
                }
                
                return self.results
            
            except (KeyboardInterrupt, UserAbortException):
                # Escalates the abort signal to the CLI orchestrator
                raise UserAbortException()

            except Exception:
                # Triggers retry logic on network errors or timeouts
                if attempt < max_retries - 1:
                    wait_time: float = (attempt + 1) * 2 + random.random()
                    self.logger.info(f"{YELLOW}[!] WHOIS lookup failed. Retrying in {wait_time:.1f}s... ({attempt + 1}/{max_retries}){RESET}")
                    time.sleep(wait_time)
                else:
                    return None
        
        return None

    # --- DATA NORMALIZATION HELPERS ---

    def _ensure_string(self, data: Any) -> str:
        """Standardizes potential list responses into a single trimmed string."""
        if not data: 
            return ""
        if isinstance(data, list):
            return str(data[0]).strip()
        return str(data).strip()

    def _ensure_list(self, data: Any) -> List[str]:
        """Standardizes any response into a unique, lowercase list of strings."""
        if not data: 
            return []
        if isinstance(data, list):
            return sorted(list(set([str(i).lower().strip() for i in data if i])))
        return [str(data).lower().strip()]

    def _format_date(self, d: Any) -> str:
        """Converts datetime objects or lists into YYYY-MM-DD strings."""
        if not d: 
            return "N/A"
        target_date: Any = d[0] if isinstance(d, list) else d
        if isinstance(target_date, datetime.datetime):
            return target_date.strftime("%Y-%m-%d")
        return str(target_date).split()[0]

    def _format_nameservers(self, ns: Any) -> List[str]:
        """Normalizes Nameserver lists."""
        return self._ensure_list(ns)

    def _format_status(self, status: Any) -> List[str]:
        """Standardizes EPP status codes by extracting the primary status label."""
        raw_list: List[str] = self._ensure_list(status)
        clean_status: List[str] = [s.split()[0] for s in raw_list]
        return list(set(clean_status))

    def _detect_infrastructure(self, ns: Any) -> Optional[str]:
        """Fingerprints Cloud/WAF providers based on nameserver patterns."""
        ns_str: str = str(ns).lower()
        if "cloudflare" in ns_str: return "Cloudflare WAF Detected"
        if "awsdns" in ns_str: return "Amazon AWS Infrastructure"
        if "googledomains" in ns_str: return "Google Cloud Infrastructure"
        if "arsys" in ns_str: return "Arsys/Nicline (Spanish Provider)"
        return None
    