#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
import hashlib
import random
import json
import time
from threading import Lock, BoundedSemaphore
from concurrent.futures import ThreadPoolExecutor

from aimenreco.ui.colors import GREEN, WHITE, CYAN, GREY, RESET, RED, YELLOW
from aimenreco.utils.helpers import get_resource_path

# Disable insecure request warnings for target environments with self-signed SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    """
    Core Discovery Engine with Intelligent Triple-DNA Filtering and Protocol Masking.
    
    This class handles active directory and file brute-forcing using a 
    multi-threaded approach. It features noise reduction through advanced 
    fingerprinting (Size, Word Count, and HTML Title) and stealth through 
    User-Agent rotation and Client-Hint simulation.
    """

    def __init__(self, url, threads, timeout, wildcard_data, logger, extensions_arg=None, sf=None):
        """
        Initializes the Discovery Engine with target configuration and DNA metrics.

        Args:
            url (str): Target base URL.
            threads (int): Maximum concurrent threads for the pool.
            timeout (int): Request timeout in seconds.
            wildcard_data (tuple): Captured DNA metrics for noise filtering.
            logger (Logger): Internal logging system for UI reporting.
            extensions_arg (list, optional): User-provided file extensions.
            sf (str|int, optional): Manual size filter(s). Supports comma-separated strings.
        """
        self.url = url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.logger = logger
        
        # Enhanced Manual Size Filter: Converts input to a set for O(1) lookups
        if sf:
            if isinstance(sf, str):
                self.sf = set(int(s.strip()) for s in sf.split(',') if s.strip().isdigit())
            else:
                self.sf = {int(sf)}
        else:
            self.sf = set()

        self.start_time = time.time()
        
        # Unpack Network DNA Metrics
        w_len = len(wildcard_data)
        self.has_w = wildcard_data[0]
        self.w_hash = wildcard_data[1]
        self.w_size = wildcard_data[2]
        self.w_status = wildcard_data[3]
        self.w_redir = wildcard_data[4] if w_len >= 5 else None
        self.w_words = wildcard_data[5] if w_len >= 6 else None
        self.w_title = wildcard_data[6] if w_len >= 7 else None

        # Extensions & Resources
        self.extensions = [e.strip().lstrip('.') for e in extensions_arg] if extensions_arg else self._load_extension_file()
        self.counter = 0
        self.protocol_filters_count = 0 
        self.results = []
        self.lock = Lock() 
        
        # Load identity and code resources
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ])
        
        http_data = self._load_json_resource("http_codes.json", {"success": [200, 204, 401, 403, 405], "redirect": [301, 302, 307, 308]})
        self.save_codes = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self):
        """Loads default file extensions from the internal resource file."""
        path = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f if line.strip() and not line.strip().startswith("#")]
        except: return []

    def _load_json_resource(self, filename, fallback):
        """Loads a JSON resource file with a fallback value in case of error."""
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f: return json.load(f)
        except: return fallback

    def _extract_title(self, html):
        """
        Extracts the HTML <title> tag content for DNA fingerprinting.
        
        Args:
            html (str): Raw HTML response body.
        Returns:
            str: Trimmed title string or 'No Title' if not found.
        """
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip()[:30] if title_match else "No Title"

    def _get_identity(self):
        """
        Generates dynamic HTTP headers with Client-Hints for stealth.
        
        Returns:
            dict: Header dictionary containing rotated User-Agent and Platform hints.
        """
        ua = random.choice(self.user_agents)
        platform = "Windows"
        if "Macintosh" in ua: platform = "macOS"
        elif "X11" in ua or "Linux" in ua: platform = "Linux"
        elif "iPhone" in ua: platform = "iOS"
        
        return {
            "User-Agent": ua,
            "Sec-CH-UA-Platform": f'"{platform}"',
            "Accept": "*/*",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }

    def prepare_wordlist(self, word_generator):
        """
        Stream-based wordlist processor that appends extensions to each base word.
        
        Args:
            word_generator: Iterator yielding base words from the dictionary.
        Yields:
            str: Original word and then each word+extension combination.
        """
        for word in word_generator:
            word = word.strip()
            if not word: continue
            yield word
            for ext in self.extensions: yield f"{word}.{ext}"
            
    def is_noise(self, status_code, content_size, content_hash, redir_loc, full_url, words, title):
        """
        Determines if a response is noise (false positive) based on Triple-DNA Fingerprinting.
        
        Check levels:
            1. Protocol Masking: Detects loops where the server redirects to the same path.
            2. DNA Comparison: Matches exact hash or status+size+words+title combination.
            3. Multiple Manual Size Filter: Checks if size is in the user-defined blacklist.

        Returns:
            tuple: (bool is_noise, str noise_type)
        """
        # 1. Protocol Masking
        if redir_loc:
            clean_redir = redir_loc.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            clean_current = full_url.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            if clean_redir == clean_current:
                return True, "protocol"

        # 2. Triple-DNA Masking (Intelligent filtering)
        if self.has_w:
            # Match by exact hash
            if content_hash == self.w_hash:
                return True, "dna"
            
            # Match by combination (Status + Size + Words + Title)
            # 15 bytes variance allowed for dynamic server headers/cookies
            if status_code == self.w_status and abs(content_size - self.w_size) <= 15:
                if self.w_words and self.w_title:
                    if words == self.w_words and title == self.w_title:
                        return True, "dna"
                else:
                    return True, "dna" 

            elif redir_loc and self.w_redir and redir_loc == self.w_redir:
                return True, "dna"

        # 3. Multiple Manual Size Filter (High Precision)
        if self.sf and content_size in self.sf:
            return True, "manual"

        return False, None

    def worker(self, path, total):
        """
        Individual thread worker that executes the HTTP request and handles reporting.
        
        Args:
            path (str): The current word/path to test.
            total (int): Total number of paths in the scan for progress tracking.
        """
        full_url = f"{self.url}/{path}"
        try:
            headers = self._get_identity()
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)
            c_words = len(r.text.split())
            c_title = self._extract_title(r.text)
            redir_loc = r.headers.get("Location", "")

            # --- TRIPLE NOISE DETECTION ---
            noise_found, noise_type = self.is_noise(r.status_code, c_size, c_hash, redir_loc, full_url, c_words, c_title)
            
            if noise_found and noise_type == "protocol":
                with self.lock: self.protocol_filters_count += 1

            # --- UI REPORTING ---
            with self.lock:
                self.counter += 1
                
                if not self.logger.quiet:
                    percent = (self.counter / total) * 100 if total > 0 else 0
                    bar = "█" * int(15 * self.counter // total)
                    status_line = f"\r{GREY}[{bar:<15}] {percent:.1f}% | {self.counter}/{total} | {path[:20]:<20}{RESET}"
                    self.logger.status(status_line)

                if not noise_found and r.status_code in self.save_codes:
                    self.logger.status("\r" + " " * 115 + "\r", flush=False)
                    status_color = GREEN if r.status_code < 300 else YELLOW
                    redir_msg = f" {GREY}-> {redir_loc}{RESET}" if redir_loc else ""
                    
                    self.logger.success(f"{status_color}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size} {CYAN}Words:{RESET} {c_words}{redir_msg}")
                    self.results.append(f"[{r.status_code}] {full_url}{redir_msg}")

        except Exception as e:
            self.logger.debug(f"Request failed for {path}: {str(e)}")
            with self.lock: self.counter += 1

    def run(self, word_generator, total_words):
        """
        Main execution loop for the multi-threaded scanner.
        
        Args:
            word_generator: Generator yielding dictionary words.
            total_words (int): Count of base words for UI progress bar calculation.
        Returns:
            list: All unique valid findings discovered during the scan.
        """
        final_generator = self.prepare_wordlist(word_generator)
        total_paths = total_words * (len(self.extensions) + 1)
        semaphore = BoundedSemaphore(self.threads * 2)

        def throttled_worker(path, total):
            try: self.worker(path, total)
            finally: semaphore.release()

        self.logger.info(f"{GREY}[*] Active Scan Phase initiated.{RESET}")
        self.logger.info(f"{GREY}[*] Using {len(self.user_agents)} rotated identities.{RESET}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for p in final_generator:
                    semaphore.acquire() 
                    executor.submit(throttled_worker, p, total_paths)
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                self.logger.info("")
                self.logger.status("\r" + " " * 115 + "\r", flush=True)
                self.logger.error("Scan aborted by user.")
            
        if not self.logger.quiet:
            self.logger.info("") 
            self.logger.info(f"{CYAN}[i] Scan summary: {len(self.results)} findings | {self.protocol_filters_count} protocol redirects filtered.{RESET}")
            
        return self.results