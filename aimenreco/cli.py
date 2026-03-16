#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
import argparse
import signal

from aimenreco.ui.banners import ManualHelpParser, show_logo
from aimenreco.ui.colors import CYAN, WHITE, GREEN, RED, BLUE, YELLOW, RESET, GREY
from aimenreco.utils.helpers import clean_url, stream_wordlist
from aimenreco.core.wildcard import WildcardAnalyzer 
from aimenreco.core.scanner import Scanner
from aimenreco.core.passive import PassiveScanner
from aimenreco.ui.logger import Logger

from aimenreco.utils.exceptions import UserAbortException

def signal_handler(sig, frame):
    """
    Handles SIGINT (Ctrl+C) by raising a custom exception.
    This allows the main loop to catch the interrupt and proceed to finalization.
    """
    raise UserAbortException()

def main():
    """
    Main entry point for the Aimenreco Discovery Framework.
    
    Orchestrates the reconnaissance workflow:
    1. Environment setup and privilege validation.
    2. Passive OSINT discovery via Certificate Transparency logs.
    3. Network DNA analysis for wildcard/catch-all detection.
    4. Multi-threaded active enumeration with real-time filtering.
    5. Graceful termination handling and result persistence.
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
    if os.geteuid() != 0:
        show_logo()
        print(f"{RED}[!] Error: Aimenreco requires root privileges.{RESET}")
        print(f"{YELLOW}[i] Try: sudo aimenreco <arguments>{RESET}\n")
        sys.exit(1)
    
    if not args.domain or not args.wordlist:
        show_logo()
        parser.print_help()
        sys.exit(1)

    # --- INITIALIZATION & SIGNAL HANDLING ---
    signal.signal(signal.SIGINT, signal_handler)
    logger = Logger(quiet=args.quiet, verbose=args.verbose)
    show_logo()
        
    url = clean_url(args.domain)
    
    if args.threads:
        threads = args.threads
    else:
        threads = 200 if args.mode == "aggressive" else 40
    
    print("-" * 80)
    print(f"{CYAN}Target: {url} | Threads: {threads} | Mode: {args.mode.upper()}{RESET}")
    print("-" * 80)
    
    results = [] # Initialize results list for the active phase
    start_time = time.time()

    try:
        # --- PASSIVE RECONNAISSANCE ---
        if args.passive:
            p_scanner = PassiveScanner(args.domain, logger=logger, output_file=args.output)
            subdomains = p_scanner.fetch_subdomains()
            
            if subdomains and args.output:
                try:
                    with open(args.output, "a") as f_out:
                        f_out.write(f"\n--- PASSIVE RECONNAISSANCE RESULTS ({args.domain}) ---\n")
                        for s in subdomains:
                            f_out.write(s + "\n")
                    logger.info(f"{BLUE}[i] Passive results cached in: {args.output}{RESET}")
                except Exception as e:
                    logger.error(f"Error saving passive results: {e}")
        
        # --- WILDCARD DNA ANALYSIS ---
        analyzer = WildcardAnalyzer(url, args.timeout)
        w_data = analyzer.check() 
        
        # --- WORDLIST GENERATOR SETUP ---
        wordlist_path = args.wordlist
        if not os.path.exists(wordlist_path):
            from aimenreco.utils.helpers import get_resource_path
            wordlist_path = get_resource_path(args.wordlist)

        if not os.path.exists(wordlist_path):
            logger.error(f"Wordlist '{args.wordlist}' not found.")
            sys.exit(1)

        print(f"\n{YELLOW}[*] Initializing wordlist stream...{RESET}")
        word_gen = stream_wordlist(wordlist_path)
        file_size = os.path.getsize(wordlist_path)
        word_count = file_size // 12

        ext_list = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

        # --- ACTIVE SCANNING PHASE ---
        scanner = Scanner(url, threads, args.timeout, w_data, logger=logger, extensions_arg=ext_list, sf=args.size_filter)
        
        # This will catch the results even if interrupted
        results = scanner.run(word_gen, word_count)

    except UserAbortException:
        # Reset cursor to start, clear the line to hide ^C, and exit gracefully
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        print(f"\n{RED}[!] Scan aborted by user. Finalizing partial results...{RESET}")
        # Fetch whatever results were found before the abort
        if 'scanner' in locals():
            results = scanner.results
        duration = time.time() - start_time # Ensure duration is calculated

    except Exception as e:
        print(f"\n{RED}[!] Unexpected Error: {e}{RESET}")
        sys.exit(1)

    # --- FINALIZATION & PERSISTENCE ---
    duration = time.time() - start_time
    print(f"\n" + "-" * 80)
    print(f"{GREEN}[✓] Scan completed in {duration:.2f}s | Findings: {len(results)}{RESET}")
    
    if args.output and results:
        try:
            with open(args.output, "a") as f_out:
                f_out.write(f"\n--- ACTIVE SCANNING RESULTS ({url}) ---\n")
                for r in results: 
                    f_out.write(r + "\n")
            print(f"{BLUE}[i] Active results appended to: {args.output}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Export error: {e}{RESET}")
    
    print("-" * 80 + "\n")

if __name__ == "__main__":
    main()