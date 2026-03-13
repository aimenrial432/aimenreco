#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import hashlib
import random
import sys
import json
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

from aimenreco.ui.colors import GREEN, WHITE, CYAN, GREY, RESET, RED
from aimenreco.utils.helpers import get_resource_path

class Scanner:
    """
    Engine for active directory enumeration and intelligent noise filtering.

    This class handles multi-threaded HTTP requests, wordlist expansion with 
    extensions, and employs 'DNA filtering' to eliminate false positives 
    caused by wildcard redirects or custom error pages.

    Attributes:
        url (str): Target base URL.
        threads (int): Maximum number of concurrent threads.
        timeout (int): Request timeout in seconds.
        has_w (bool): Indicates if the target has a wildcard behavior.
        w_hash (str): MD5 hash of the server's wildcard response content.
        w_size (int): Byte size of the server's wildcard response.
        extensions (list): List of file extensions to append to paths.
    """

    def __init__(self, url, threads, timeout, wildcard_data, extensions_arg=None):
        """
        Initializes the Scanner with target data and configuration.

        Args:
            url (str): The target URL to scan.
            threads (int): Concurrent threads for the execution.
            timeout (int): Seconds to wait for server response.
            wildcard_data (tuple): Contains (has_wildcard, content_hash, content_size).
            extensions_arg (list, optional): User-provided extensions. Defaults to None.
        """
        self.url = url
        self.threads = threads
        self.timeout = timeout
        
        self.has_w, self.w_hash, self.w_size = wildcard_data
        
        if extensions_arg:
            self.extensions = [e.strip().lstrip('.') for e in extensions_arg]
        else:
            self.extensions = self._load_extension_file()
        
        self.counter = 0
        self.results = []
        self.lock = Lock() 
        
        self.user_agents = self._load_json_resource("user_agents.json", ["Aimenreco/3.0"])
        http_data = self._load_json_resource("http_codes.json", {"success": [200], "redirect": [301, 302]})
        self.save_codes = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self):
        """
        Loads extensions from the internal resource file.

        Returns:
            list: Cleaned list of extensions (e.g., ['php', 'html']).
        """
        path = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f 
                        if line.strip() and not line.strip().startswith("#")]
        except:
            return []

    def _load_json_resource(self, filename, fallback):
        """
        Generic loader for JSON configuration files.

        Args:
            filename (str): Name of the file within resources.
            fallback (any): Data to return if loading fails.

        Returns:
            dict/list: Parsed JSON data or fallback.
        """
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except:
            return fallback

    def prepare_wordlist(self, raw_words):
        """
        Expands the base wordlist by appending configured extensions.

        Args:
            raw_words (list): List of base words from the wordlist file.

        Returns:
            list: De-duplicated list of paths including base words and extensions.
        """
        final_list = []
        for word in raw_words:
            word = word.strip()
            if not word: continue
            final_list.append(word)
            for ext in self.extensions:
                final_list.append(f"{word}.{ext}")
        return list(dict.fromkeys(final_list))

    def worker(self, path, total):
        """
        Individual thread worker that performs HTTP requests and filters noise.

        Implements 'DNA filtering' logic:
        1. Compares response hash with wildcard hash.
        2. Checks for redundant status codes (e.g., universal 301s).
        3. Analyzes response size variance to detect false positives.

        Args:
            path (str): The specific path to test.
            total (int): Total number of paths for progress tracking.
        """
        full_url = f"{self.url}/{path}"
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, 
                             headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)

            if self.has_w:
                # Rule 1: Identity filtering (Same content as wildcard)
                if c_hash == self.w_hash:
                    with self.lock: self.counter += 1
                    return

                # Rule 2: State-based noise reduction (e.g., Maristak logic)
                if r.status_code == 301:
                    with self.lock: self.counter += 1
                    return
                
                # Rule 3: Fuzzy size matching (Threshold: 10 bytes)
                if abs(c_size - self.w_size) < 10:
                    with self.lock: self.counter += 1
                    return

            with self.lock:
                self.counter += 1
                sys.stdout.write(f"\r{GREY}[{self.counter}/{total}]{RESET} ")
                
                if r.status_code in self.save_codes:
                    sys.stdout.write(f"\r{GREEN}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size}\n")
                    self.results.append(f"[{r.status_code}] {full_url}")
                    sys.stdout.flush()
        except:
            with self.lock: self.counter += 1

    def run(self, words):
        """
        Orchestrates the scanning process using a thread pool.

        Args:
            words (list): Base wordlist to be processed.

        Returns:
            list: Successful findings (Status Code + URL).
        """
        final_paths = self.prepare_wordlist(words)
        total = len(final_paths)
        print(f"{GREY}[*] Expanded wordlist: {total} paths prepared.{RESET}\n")
        
        executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            for p in final_paths:
                executor.submit(self.worker, p, total)
            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
        return self.results