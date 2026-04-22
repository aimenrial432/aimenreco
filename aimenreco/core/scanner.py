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
from typing import List, Set, Dict, Any, Optional, Union, Generator, Tuple

from aimenreco.ui.colors import GREEN, WHITE, CYAN, GREY, RESET, RED, YELLOW
from aimenreco.ui.logger import Logger
from aimenreco.utils.helpers import get_resource_path
from aimenreco.models import WildcardDNA, ScanResult

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

    def __init__(self, url: str, threads: int, timeout: float, 
                 wildcard_data: Union[WildcardDNA, tuple], 
                 logger: Logger, 
                 extensions_arg: Optional[List[str]] = None, 
                 sf: Optional[Union[str, int]] = None) -> None:
        """
        Initializes the Discovery Engine with target configuration and DNA metrics.
        """
        self.url: str = url.rstrip('/')
        self.threads: int = threads
        self.timeout: float = timeout
        self.logger: Logger = logger
        
        # Enhanced Manual Size Filter: Converts input to a set for O(1) lookups
        self.sf: Set[int] = set()
        if sf:
            if isinstance(sf, str):
                self.sf = set(int(s.strip()) for s in sf.split(',') if s.strip().isdigit())
            else:
                self.sf = {int(sf)}

        self.start_time: float = time.time()
        
        # Unpack Network DNA Metrics (Compatible with legacy tuple and new Dataclass)
        if isinstance(wildcard_data, WildcardDNA):
            self.has_w: bool = wildcard_data.is_wildcard
            self.w_hash: Optional[str] = None # Hash not in current DNA dataclass
            self.w_size: int = wildcard_data.content_length
            self.w_status: int = wildcard_data.status_code
            self.w_redir: Optional[str] = None
            self.w_words: Optional[int] = None
            self.w_title: Optional[str] = None
        else:
            w_len: int = len(wildcard_data)
            self.has_w = wildcard_data[0]
            self.w_hash = wildcard_data[1]
            self.w_size = wildcard_data[2]
            self.w_status = wildcard_data[3]
            self.w_redir = wildcard_data[4] if w_len >= 5 else None
            self.w_words = wildcard_data[5] if w_len >= 6 else None
            self.w_title = wildcard_data[6] if w_len >= 7 else None

        # Extensions & Resources
        self.extensions: List[str] = [e.strip().lstrip('.') for e in extensions_arg] if extensions_arg else self._load_extension_file()
        self.counter: int = 0
        self.protocol_filters_count: int = 0 
        self.results: List[str] = []
        self.lock: Lock = Lock() 
        
        # Load identity and code resources
        self.user_agents: List[str] = self._load_json_resource("user_agents.json", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ])
        
        http_data: Dict[str, List[int]] = self._load_json_resource("http_codes.json", {"success": [200, 204, 401, 403, 405], "redirect": [301, 302, 307, 308]})
        self.save_codes: Set[int] = set(http_data.get("success", []) + http_data.get("redirect", []))

    def _load_extension_file(self) -> List[str]:
        """Loads default file extensions from the internal resource file."""
        path: str = get_resource_path("extensions.txt")
        try:
            with open(path, 'r') as f:
                return [line.strip().lstrip('.') for line in f if line.strip() and not line.strip().startswith("#")]
        except Exception: 
            return []

    def _load_json_resource(self, filename: str, fallback: Any) -> Any:
        """Loads a JSON resource file with a fallback value in case of error."""
        path: str = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f: 
                return json.load(f)
        except Exception: 
            return fallback

    def _extract_title(self, html: str) -> str:
        """
        Extracts the HTML <title> tag content for DNA fingerprinting.
        """
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip()[:30] if title_match else "No Title"

    def _get_identity(self) -> Dict[str, str]:
        """
        Generates dynamic HTTP headers with Client-Hints for stealth.
        """
        ua: str = random.choice(self.user_agents)
        platform: str = "Windows"
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

    def prepare_wordlist(self, word_generator: Generator[str, None, None]) -> Generator[str, None, None]:
        """
        Stream-based wordlist processor that appends extensions to each base word.
        """
        for word in word_generator:
            word = word.strip()
            if not word: continue
            yield word
            for ext in self.extensions: 
                yield f"{word}.{ext}"
            
    def is_noise(self, status_code: int, content_size: int, content_hash: str, 
                 redir_loc: str, full_url: str, words: int, title: str) -> Tuple[bool, Optional[str]]:
        """
        Determines if a response is noise (false positive) based on Triple-DNA Fingerprinting.
        """
        # 1. Protocol Masking
        if redir_loc:
            clean_redir: str = redir_loc.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            clean_current: str = full_url.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")
            if clean_redir == clean_current:
                return True, "protocol"

        # 2. Triple-DNA Masking (Intelligent filtering)
        if self.has_w:
            if content_hash == self.w_hash:
                return True, "dna"
            
            if status_code == self.w_status and abs(content_size - self.w_size) <= 15:
                if self.w_words is not None and self.w_title is not None:
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

    def worker(self, path: str, total: int) -> None:
        """
        Individual thread worker that executes the HTTP request and handles reporting.
        """
        full_url: str = f"{self.url}/{path}"
        try:
            headers: Dict[str, str] = self._get_identity()
            r = requests.get(full_url, timeout=self.timeout, allow_redirects=False, headers=headers, verify=False)
            
            c_hash: str = hashlib.md5(r.content).hexdigest()
            c_size: int = len(r.content)
            c_words: int = len(r.text.split())
            c_title: str = self._extract_title(r.text)
            redir_loc: str = r.headers.get("Location", "")

            # --- TRIPLE NOISE DETECTION ---
            noise_found, noise_type = self.is_noise(r.status_code, c_size, c_hash, redir_loc, full_url, c_words, c_title)
            
            if noise_found and noise_type == "protocol":
                with self.lock: 
                    self.protocol_filters_count += 1

            # --- UI REPORTING ---
            with self.lock:
                self.counter += 1
                
                if not self.logger.quiet:
                    percent: float = (self.counter / total) * 100 if total > 0 else 0
                    bar_count: int = int(15 * self.counter // total) if total > 0 else 0
                    bar: str = "█" * bar_count
                    status_line: str = f"\r{GREY}[{bar:<15}] {percent:.1f}% | {self.counter}/{total} | {path[:20]:<20}{RESET}"
                    self.logger.status(status_line)

                if not noise_found and r.status_code in self.save_codes:
                    self.logger.status("\r" + " " * 115 + "\r", flush=False)
                    status_color: str = GREEN if r.status_code < 300 else YELLOW
                    redir_msg: str = f" {GREY}-> {redir_loc}{RESET}" if redir_loc else ""
                    
                    self.logger.success(f"{status_color}[{r.status_code}]{RESET} {WHITE}{full_url:<45}{RESET} {CYAN}Size:{RESET} {c_size} {CYAN}Words:{RESET} {c_words}{redir_msg}")
                    self.results.append(f"[{r.status_code}] {full_url}{redir_msg}")

        except Exception:
            with self.lock: 
                self.counter += 1

    def run(self, word_generator: Generator[str, None, None], total_words: int) -> List[str]:
        """
        Main execution loop for the multi-threaded scanner.
        """
        final_generator: Generator[str, None, None] = self.prepare_wordlist(word_generator)
        total_paths: int = total_words * (len(self.extensions) + 1)
        semaphore: BoundedSemaphore = BoundedSemaphore(self.threads * 2)

        def throttled_worker(path_worker: str, total_worker: int) -> None:
            try: 
                self.worker(path_worker, total_worker)
            finally: 
                semaphore.release()

        self.logger.process(f"Active Scan Phase initiated.{RESET}")
        self.logger.process(f"Using {len(self.user_agents)} rotated identities.{RESET}")

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
            self.logger.info(f"Scan summary: {len(self.results)} findings | {self.protocol_filters_count} protocol redirects filtered.{RESET}")
            
        return self.results