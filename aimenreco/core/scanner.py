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
    Optimized for terminal performance using the internal Logger system.
    """

    def __init__(self, url, threads, timeout, wildcard_data, logger, extensions_arg=None, sf=None):
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
        
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.2"])
        http_data = self._load_json_resource("http_codes.json", {"success": [200, 204, 401, 403, 405], "redirect": [301, 302, 307, 308]})
        self.save_codes = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self):
        path = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f if line.strip() and not line.strip().startswith("#")]
        except: return []

    def _load_json_resource(self, filename, fallback):
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f: return json.load(f)
        except: return fallback

    def prepare_wordlist(self, word_generator):
        for word in word_generator:
            word = word.strip()
            if not word: continue
            yield word
            for ext in self.extensions: yield f"{word}.{ext}"

    def worker(self, path, total):
        """Worker executing requests and filtering noise using Logger.status."""
        full_url = f"{self.url}/{path}"
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)
            redir_loc = r.headers.get("Location", "")

            # --- NOISE DETECTION ---
            is_noise = False
            
            # 1. Protocol Masking
            if redir_loc:
                clean_redir = redir_loc.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
                clean_current = full_url.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
                if clean_redir == clean_current:
                    with self.lock: self.protocol_filters_count += 1
                    is_noise = True

            # 2. DNA / Wildcard Masking
            if not is_noise and self.has_w:
                if c_hash == self.w_hash or (r.status_code == self.w_status and abs(c_size - self.w_size) <= 15):
                    is_noise = True
                elif redir_loc and self.w_redir and redir_loc == self.w_redir:
                    is_noise = True

            # 3. Manual Size Filter
            if not is_noise and self.sf is not None and c_size == self.sf:
                is_noise = True

            # --- UI REPORTING VIA LOGGER ---
            with self.lock:
                self.counter += 1
                
                # Update progress bar (The Heartbeat)
                if not self.logger.quiet:
                    percent = (self.counter / total) * 100 if total > 0 else 0
                    bar = "█" * int(15 * self.counter // total)
                    # Use logger.status for the '\r' line
                    status_line = f"\r{GREY}[{bar:<15}] {percent:.1f}% | {self.counter}/{total} | {path[:20]:<20}{RESET}"
                    self.logger.status(status_line)

                # Process valid findings
                if not is_noise and r.status_code in self.save_codes:
                    # Clear line for hit using status without flush to prep for next success call
                    self.logger.status("\r" + " " * 110 + "\r", flush=False)
                    
                    status_color = GREEN if r.status_code < 300 else YELLOW
                    redir_msg = f" {GREY}-> {redir_loc}{RESET}" if redir_loc else ""
                    
                    self.logger.success(f"{status_color}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size}{redir_msg}")
                    self.results.append(f"[{r.status_code}] {full_url}{redir_msg}")

        except Exception as e:
            self.logger.debug(f"Request failed for {path}: {str(e)}")
            with self.lock: self.counter += 1

    def run(self, word_generator, total_words):
        final_generator = self.prepare_wordlist(word_generator)
        total_paths = total_words * (len(self.extensions) + 1)
        semaphore = BoundedSemaphore(self.threads * 2)

        def throttled_worker(path, total):
            try: self.worker(path, total)
            finally: semaphore.release()

        self.logger.info(f"{GREY}[*] Active Scan Phase initiated.{RESET}")
        self.logger.info(f"{GREY}[*] Protocol Masking: Enabled (Ignoring schema/www upgrades){RESET}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for p in final_generator:
                    semaphore.acquire() 
                    executor.submit(throttled_worker, p, total_paths)
            except KeyboardInterrupt:
                #Clean threads
                executor.shutdown(wait=False, cancel_futures=True)
                
                #Visual cleanning
                self.logger.info("")
                self.logger.status("\r" + " " * 115 + "\r", flush=True)
                self.logger.error("Scan aborted by user.")
            
        if not self.logger.quiet:
            self.logger.info("") # Newline for summary
            self.logger.info(f"{CYAN}[i] Scan summary: {len(self.results)} findings | {self.protocol_filters_count} protocol-only redirects filtered.{RESET}")
            
        return self.results