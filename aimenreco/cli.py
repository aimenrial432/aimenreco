#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
import argparse

from aimenreco.ui.banners import ManualHelpParser, show_logo
from aimenreco.ui.colors import CYAN, WHITE, GREEN, RED, BLUE, YELLOW, RESET, GREY
from aimenreco.utils.helpers import clean_url, stream_wordlist
from aimenreco.core.wildcard import WildcardAnalyzer 
from aimenreco.core.scanner import Scanner
from aimenreco.core.passive import PassiveScanner
from aimenreco.ui.logger import Logger

def main():
    # --- PHASE 0: ARGUMENT PARSING ---
    parser = ManualHelpParser(add_help=False)
    parser.add_argument("-d", "--domain")
    parser.add_argument("-w", "--wordlist")
    parser.add_argument("-m", "--mode", default="std")
    parser.add_argument("-x", "--extensions", default="")
    parser.add_argument("-t", "--threads", type=int)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-p", "--passive", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args, unknown = parser.parse_known_args()

    if args.help:
        show_logo()
        parser.print_help()
        sys.exit(0)

    # --- PRIVILEGE CHECK ---
    if os.geteuid() != 0:
        show_logo()
        print(f"{RED}[!] Error: Aimenreco requires root privileges.{RESET}")
        print(f"{YELLOW}[i] Try: sudo aimenreco <arguments>{RESET}\n")
        sys.exit(1)
    
    if not args.domain or not args.wordlist:
        show_logo()
        parser.print_help()
        sys.exit(1)

    # --- INITIALIZATION ---
    logger = Logger(quiet=args.quiet, verbose=args.verbose)
    
    # The log appears always (Tools Tag)
    show_logo()
        
    url = clean_url(args.domain)
    threads = args.threads or (200 if args.mode == "aggressive" else 40)
    
    print("-" * 80)
    print(f"{CYAN}Target: {url} | Threads: {threads} | Mode: {args.mode.upper()}{RESET}")
    print("-" * 80)
    
    # --- PASSIVE RECONNAISSANCE ---
    if args.passive:
        p_scanner = PassiveScanner(args.domain, logger=logger)
        subdomains = p_scanner.fetch_subdomains()
        if subdomains:
            for s in subdomains:
                print(f"  {GREEN}└─{RESET} {s}")
    
    # --- WILDCARD DNA ANALYSIS ---
    analyzer = WildcardAnalyzer(url, args.timeout)
    w_data = analyzer.check() 
    
    # --- WORDLIST GENERATOR SETUP ---
    # Smart search: Check local directory first, then fallback to package resources
    wordlist_path = args.wordlist
    if not os.path.exists(wordlist_path):
        from aimenreco.utils.helpers import get_resource_path
        wordlist_path = get_resource_path(args.wordlist)

    logger.info(f"{YELLOW}[*] Initializing memory-efficient wordlist stream...{RESET}")
    
    try:
        # Final validation of the path
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"'{args.wordlist}' not found locally or in resources.")
            
        # Count lines using the validated path
        word_count = sum(1 for _ in stream_wordlist(wordlist_path))
        if word_count == 0:
            raise ValueError("Wordlist is empty.")
            
    except Exception as e:
        print(f"{RED}[!] Wordlist Error: {e}{RESET}")
        sys.exit(1)

    # Re-initialize the generator using the VALIDATED path
    word_gen = stream_wordlist(wordlist_path)
    
    ext_list = None
    if args.extensions:
        ext_list = [e.strip() for e in args.extensions.split(",")]

    # --- ACTIVE SCANNING PHASE ---
    scanner = Scanner(url, threads, args.timeout, w_data, logger=logger, extensions_arg=ext_list)
    start_time = time.time()
    
    try:
        # We pass both the generator and the base count
        results = scanner.run(word_gen, word_count)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] KeyboardInterrupt: Shutting down threads...{RESET}")
        os._exit(0) 

    # --- FINALIZATION & PERSISTENCE ---
    duration = time.time() - start_time
    print(f"\n" + "-" * 80)
    print(f"{GREEN}[✓] Scan completed in {duration:.2f}s | Findings: {len(results)}{RESET}")
    
    if args.output and results:
        try:
            with open(args.output, "w") as f_out:
                for r in results: 
                    f_out.write(r + "\n")
            print(f"{BLUE}[i] Results exported to: {args.output}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Export error: {e}{RESET}")
    print("-" * 80 + "\n")

if __name__ == "__main__":
    main()