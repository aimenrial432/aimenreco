#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import hashlib
import random
import sys
import json
from threading import Lock, BoundedSemaphore
from concurrent.futures import ThreadPoolExecutor

from aimenreco.ui.colors import GREEN, WHITE, CYAN, GREY, RESET, RED
from aimenreco.utils.helpers import get_resource_path

class Scanner:
    """
    Engine for active directory enumeration and intelligent noise filtering.
    """

    def __init__(self, url, threads, timeout, wildcard_data, logger, extensions_arg=None):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.logger = logger # <--- Injected Logger
        
        self.has_w, self.w_hash, self.w_size = wildcard_data
        
        if extensions_arg:
            self.extensions = [e.strip().lstrip('.') for e in extensions_arg]
        else:
            self.extensions = self._load_extension_file()
        
        self.counter = 0
        self.results = []
        self.lock = Lock() 
        
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.1"])
        http_data = self._load_json_resource("http_codes.json", {"success": [200], "redirect": [301, 302]})
        self.save_codes = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self):
        path = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f 
                        if line.strip() and not line.strip().startswith("#")]
        except:
            return []

    def _load_json_resource(self, filename, fallback):
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except:
            return fallback

    def prepare_wordlist(self, word_generator):
        for word in word_generator:
            word = word.strip()
            if not word: continue
            yield word
            for ext in self.extensions:
                yield f"{word}.{ext}"

    def worker(self, path, total):
        full_url = f"{self.url}/{path}"
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, 
                             headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)

            # --- INTELLIGENT DNA FILTERING (WITH VERBOSE LOGGING) ---
            if self.has_w:
                if c_hash == self.w_hash:
                    self.logger.debug(f"Discarded: {path} (DNA Match: MD5 Hash)")
                    with self.lock: self.counter += 1
                    return
                if r.status_code == 301 and not 301 in self.save_codes:
                    # Only discard 301 if it's not explicitly in our success codes
                    self.logger.debug(f"Discarded: {path} (DNA Match: Universal Redirect)")
                    with self.lock: self.counter += 1
                    return
                if abs(c_size - self.w_size) < 10:
                    self.logger.debug(f"Discarded: {path} (DNA Match: Size Variance)")
                    with self.lock: self.counter += 1
                    return

            with self.lock:
                self.counter += 1
                # Progress status (Hidden in Quiet mode)
                self.logger.status(f"\r{GREY}[{self.counter}/{total}]{RESET} ", end="", flush=True)
                
                if r.status_code in self.save_codes:
                    # Success findings (Always printed)
                    self.logger.success(f"\r{GREEN}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size}")
                    self.results.append(f"[{r.status_code}] {full_url}")

        except Exception as e:
            self.logger.debug(f"Request Error on {path}: {str(e)}")
            with self.lock: self.counter += 1

    def run(self, word_generator, total_words):
        final_generator = self.prepare_wordlist(word_generator)
        total_paths = total_words * (len(self.extensions) + 1)
        
        semaphore = BoundedSemaphore(self.threads * 2)

        def throttled_worker(path, total):
            try:
                self.worker(path, total)
            finally:
                semaphore.release()

        self.logger.info(f"{GREY}[*] Memory-safe mode active: Processing {total_paths} potential paths.{RESET}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for p in final_generator:
                    semaphore.acquire()
                    executor.submit(throttled_worker, p, total_paths)
            except KeyboardInterrupt:
                # Handled in CLI but kept for safety
                pass 
            
        return self.results