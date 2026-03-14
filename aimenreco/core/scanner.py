#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import hashlib
import random
import sys
import json
from threading import Lock, BoundedSemaphore # <--- Added BoundedSemaphore
from concurrent.futures import ThreadPoolExecutor

from aimenreco.ui.colors import GREEN, WHITE, CYAN, GREY, RESET, RED
from aimenreco.utils.helpers import get_resource_path

class Scanner:
    """
    Engine for active directory enumeration and intelligent noise filtering.
    
    Optimized with BoundedSemaphore to prevent memory exhaustion when 
    processing massive wordlists via generators.
    """

    def __init__(self, url, threads, timeout, wildcard_data, extensions_arg=None):
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

            if self.has_w:
                if c_hash == self.w_hash:
                    with self.lock: self.counter += 1
                    return
                if r.status_code == 301:
                    with self.lock: self.counter += 1
                    return
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

    def run(self, word_generator, total_words):
        """
        Orchestrates the scan using a semaphore to control memory pressure.
        """
        final_generator = self.prepare_wordlist(word_generator)
        total_paths = total_words * (len(self.extensions) + 1)
        
        # This semaphore ensures we only queue a small number of tasks at once
        # If threads=40, it will only allow 80 tasks in RAM at any given time.
        semaphore = BoundedSemaphore(self.threads * 2)

        def throttled_worker(path, total):
            try:
                self.worker(path, total)
            finally:
                semaphore.release() # Task finished, free a slot in the queue

        print(f"{GREY}[*] Memory-safe mode active: Processing {total_paths} potential paths.{RESET}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for p in final_generator:
                    semaphore.acquire() # Block here if the queue is full
                    executor.submit(throttled_worker, p, total_paths)
            except KeyboardInterrupt:
                print(f"\n{RED}[!] Interrupt received. Cleaning up...{RESET}")
                # We don't need to shutdown here, 'with' block handles it
            
        return self.results