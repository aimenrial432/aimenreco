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
    """
    Main entry point for the Aimenreco Discovery Framework.
    
    This function orchestrates the entire reconnaissance workflow:
    1. Argument parsing and privilege validation.
    2. Passive reconnaissance (OSINT) via CT logs.
    3. Network DNA analysis to identify wildcard/catch-all behaviors.
    4. Multi-threaded active directory enumeration with real-time filtering.
    5. Result persistence and session finalization.
    """

    # --- PHASE 0: ARGUMENT PARSING ---
    parser = ManualHelpParser(add_help=False)
    parser.add_argument("-d", "--domain", help="Target domain or URL")
    parser.add_argument("-w", "--wordlist", help="Path to the dictionary file")
    parser.add_argument("-m", "--mode", default="std", help="Scanning profile: std or aggressive")
    parser.add_argument("-x", "--extensions", default="", help="Comma-separated list of extensions (e.g. php,txt)")
    parser.add_argument("-t", "--threads", type=int, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="Save findings to a text file")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")
    parser.add_argument("-p", "--passive", action="store_true", help="Enable passive subdomain discovery")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppresses non-essential output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed debug logging")
    parser.add_argument("-sf", "--size-filter", type=int, help="Manual size filter")
    
    args, unknown = parser.parse_known_args()

    if args.help:
        show_logo()
        parser.print_help()
        sys.exit(0)

    # --- PRIVILEGE CHECK ---
    # Root is required for low-level network operations and system-wide installations
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
    show_logo()
        
    url = clean_url(args.domain)
    
    # Threading Logic: Prioritize manual flag '-t', otherwise fall back to profile defaults
    if args.threads:
        threads = args.threads
    else:
        threads = 200 if args.mode == "aggressive" else 40
    
    print("-" * 80)
    print(f"{CYAN}Target: {url} | Threads: {threads} | Mode: {args.mode.upper()}{RESET}")
    print("-" * 80)
    
    # --- PASSIVE RECONNAISSANCE ---
    # Scrapes public Certificate Transparency logs for subdomain discovery
    if args.passive:
        p_scanner = PassiveScanner(args.domain, logger=logger)
        subdomains = p_scanner.fetch_subdomains()
        if subdomains:
            for s in subdomains:
                print(f"  {GREEN}└─{RESET} {s}")
    
    # --- WILDCARD DNA ANALYSIS ---
    # Heuristic phase to identify if the server uses global redirects or custom 404s
    analyzer = WildcardAnalyzer(url, args.timeout)
    w_data = analyzer.check() 
    
    # --- WORDLIST GENERATOR SETUP ---
    # Dual-lookup strategy for wordlist path resolution
    wordlist_path = args.wordlist
    if not os.path.exists(wordlist_path):
        from aimenreco.utils.helpers import get_resource_path
        wordlist_path = get_resource_path(args.wordlist)

    if not os.path.exists(wordlist_path):
        logger.error(f"Wordlist '{args.wordlist}' not found locally or in resources.")
        sys.exit(1)

    # Performance optimization: Instead of counting lines (slow for million-line files),
    # we use the file size to estimate or simply report current progress.
    logger.info(f"{YELLOW}[*] Initializing wordlist stream...{RESET}")
    
    # Resetting the generator for the active scanning phase
    word_gen = stream_wordlist(wordlist_path)
    
    # Estimate total words based on file size (avg 12 bytes per word) for a rough UI total
    # If the file is small, word_count is useful, otherwise we just track progress.
    file_size = os.path.getsize(wordlist_path)
    word_count = file_size // 12  # Rough estimation to avoid the freezing sum() call

    ext_list = None
    if args.extensions:
        ext_list = [e.strip() for e in args.extensions.split(",")]

    # --- ACTIVE SCANNING PHASE ---
    # Core discovery engine with real-time DNA filtering
    scanner = Scanner(url, threads, args.timeout, w_data, logger=logger, extensions_arg=ext_list, sf=args.size_filter)
    start_time = time.time()
    
    try:
        # We pass 0 if we don't want a fixed total, or the estimation
        results = scanner.run(word_gen, word_count)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] KeyboardInterrupt: Shutting down threads...{RESET}")
        os._exit(0) 

    # --- FINALIZATION & PERSISTENCE ---
    # Calculate performance metrics and export discovered assets
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