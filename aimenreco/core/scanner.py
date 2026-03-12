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
    def __init__(self, url, threads, timeout, wildcard_data, extensions_arg=None):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        
        # ADN del servidor
        self.has_w, self.w_hash, self.w_size = wildcard_data
        
        # Lógica de Extensiones: Si no hay argumento, cargamos del archivo
        if extensions_arg:
            self.extensions = [e.strip().lstrip('.') for e in extensions_arg]
        else:
            self.extensions = self._load_extension_file()
        
        self.counter = 0
        self.results = []
        self.lock = Lock() 
        
        self.user_agents = self._load_json_resource("user_agents.json", ["DirForcer/4.0"])
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

    def prepare_wordlist(self, raw_words):
        """Expande el diccionario base con las extensiones."""
        final_list = []
        for word in raw_words:
            word = word.strip()
            if not word: continue
            final_list.append(word)
            for ext in self.extensions:
                final_list.append(f"{word}.{ext}")
        return list(dict.fromkeys(final_list))

    def worker(self, path, total):
        full_url = f"{self.url}/{path}"
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, 
                             headers=headers, verify=False)
            
            c_hash = hashlib.md5(r.content).hexdigest()
            c_size = len(r.content)

            if self.has_w:
                if c_hash == self.w_hash or abs(c_size - self.w_size) < 15:
                    with self.lock: self.counter += 1
                    return

            with self.lock:
                self.counter += 1
                sys.stdout.write(f"\r{GREY}[{self.counter}/{total}]{RESET} ")
                if r.status_code in self.save_codes:
                    print(f"{GREEN}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size}")
                    self.results.append(f"[{r.status_code}] {full_url}")
        except:
            with self.lock: self.counter += 1

    def run(self, words):
        """Prepara y ejecuta el escaneo."""
        final_paths = self.prepare_wordlist(words)
        total = len(final_paths)
        print(f"{GREY}[*] Diccionario expandido: {total} rutas preparadas.{RESET}\n")
        
        executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            for p in final_paths:
                executor.submit(self.worker, p, total)
            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            print(f"\n\n{RED}[!] Cancelando escaneo...{RESET}")
            executor.shutdown(wait=False, cancel_futures=True)
        return self.results