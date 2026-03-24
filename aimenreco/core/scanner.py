#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    Core Discovery Engine with Intelligent DNA Filtering and Protocol Masking.
    
    This class handles active directory and file brute-forcing using a 
    multi-threaded approach. It features noise reduction through response 
    fingerprinting (MD5 and size variance) and stealth through User-Agent 
    rotation and Client-Hint simulation.
    """

    def __init__(self, url, threads, timeout, wildcard_data, logger, extensions_arg=None, sf=None):
        """
        Initializes the Discovery Engine.

        Args:
            url (str): Target base URL.
            threads (int): Maximum concurrent threads.
            timeout (int): Request timeout in seconds.
            wildcard_data (tuple): DNA/Wildcard metrics for noise filtering.
            logger (Logger): Internal logging system for UI reporting.
            extensions_arg (list, optional): List of file extensions to append.
            sf (int, optional): Specific size filter provided by user.
        """
        self.url = url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.logger = logger
        self.sf = sf 
        self.start_time = time.time()
        
        # Unpack Network DNA
        if len(wildcard_data) == 5:
            self.has_w, self.w_hash, self.w_size, self.w_status, self.w_redir = wildcard_data
        else:
            self.has_w, self.w_hash, self.w_size, self.w_status = wildcard_data
            self.w_redir = None

        # Extensions & Resources
        self.extensions = [e.strip().lstrip('.') for e in extensions_arg] if extensions_arg else self._load_extension_file()
        self.counter = 0
        self.protocol_filters_count = 0 
        self.results = []
        self.lock = Lock() 
        
        # Load rotation resources from the centralized JSON
        self.user_agents = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ])
        
        # Load HTTP configuration for valid response identifying
        http_data = self._load_json_resource("http_codes.json", {"success": [200, 204, 401, 403, 405], "redirect": [301, 302, 307, 308]})
        self.save_codes = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self):
        """Internal helper to load extensions from static text file."""
        path = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f if line.strip() and not line.strip().startswith("#")]
        except: return []

    def _load_json_resource(self, filename, fallback):
        """Internal helper to load JSON data from package resources."""
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f: return json.load(f)
        except: return fallback

    def _get_identity(self):
        """Generates dynamic headers with Client-Hints for active scanning stealth."""
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
        """Processes the input wordlist and yields words with appended extensions."""
        for word in word_generator:
            word = word.strip()
            if not word: continue
            yield word
            for ext in self.extensions: yield f"{word}.{ext}"
            
    def is_noise(self, status_code, content_size, content_hash, redir_loc, full_url):
        """
        Determines if a response is noise based on DNA signatures or Protocol Masking.
        
        Returns:
            tuple: (is_noise: bool, type: str)
        """
        # 1. Protocol Masking (Identifies redundant redirects like http -> https)
        if redir_loc:
            clean_redir = redir_loc.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            clean_current = full_url.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            if clean_redir == clean_current:
                return True, "protocol"

        # 2. DNA / Wildcard Masking (Matches catch-all signatures)
        if self.has_w:
            if content_hash == self.w_hash or (status_code == self.w_status and abs(content_size - self.w_size) <= 15):
                return True, "dna"
            elif redir_loc and self.w_redir and redir_loc == self.w_redir:
                return True, "dna"

        # 3. Manual Size Filter
        if self.sf is not None and content_size == self.sf:
            return True, "manual"

        return False, None

    def worker(self, path, total):
        """Worker thread executing HTTP requests and filtering results via UI logger."""
        full_url = f"{self.url}/{path}"
        try:
            headers = self._get_identity()
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)
            redir_loc = r.headers.get("Location", "")

            # --- NOISE DETECTION ---
            noise_found, noise_type = self.is_noise(r.status_code, c_size, c_hash, redir_loc, full_url)
            
            if noise_found and noise_type == "protocol":
                with self.lock: self.protocol_filters_count += 1

            # --- UI REPORTING VIA LOGGER ---
            with self.lock:
                self.counter += 1
                
                # Update progress bar status
                if not self.logger.quiet:
                    percent = (self.counter / total) * 100 if total > 0 else 0
                    bar = "█" * int(15 * self.counter // total)
                    status_line = f"\r{GREY}[{bar:<15}] {percent:.1f}% | {self.counter}/{total} | {path[:20]:<20}{RESET}"
                    self.logger.status(status_line)

                # Process valid findings and clear status bar
                if not noise_found and r.status_code in self.save_codes:
                    self.logger.status("\r" + " " * 115 + "\r", flush=False)
                    
                    status_color = GREEN if r.status_code < 300 else YELLOW
                    redir_msg = f" {GREY}-> {redir_loc}{RESET}" if redir_loc else ""
                    
                    self.logger.success(f"{status_color}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size}{redir_msg}")
                    self.results.append(f"[{r.status_code}] {full_url}{redir_msg}")

        except Exception as e:
            self.logger.debug(f"Request failed for {path}: {str(e)}")
            with self.lock: self.counter += 1

    def run(self, word_generator, total_words):
        """
        Starts the multi-threaded scanning process.
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