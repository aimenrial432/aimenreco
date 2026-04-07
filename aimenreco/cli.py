#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
import argparse
import signal

from aimenreco.ui.banners import ManualHelpParser, show_logo
from aimenreco.ui.colors import CYAN, WHITE, GREEN, RED, BLUE, YELLOW, RESET, GREY
from aimenreco.utils.helpers import clean_url, stream_wordlist, prepare_wordlist
from aimenreco.core.wildcard import WildcardAnalyzer 
from aimenreco.core.scanner import Scanner
from aimenreco.core.passive import PassiveScanner
from aimenreco.ui.logger import Logger
from aimenreco.utils.reporter import Reporter

from aimenreco.utils.exceptions import UserAbortException

from aimenreco import __version__

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
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}',help="Show program's version number and exit")
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
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv, -vvv)")
    parser.add_argument("-sf", "--size-filter", type=str, help="Manual size filter (e.g. 808,0,1500)")
    
    
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
    reporter = Reporter(args.output, logger=logger)
    show_logo()
        
    url = clean_url(args.domain)
    
    # Clean thread calculation
    threads = args.threads or (200 if args.mode == "aggressive" else 40)
    
    print("-" * 80)
    print(f"{CYAN}Target: {url} | Threads: {threads} | Mode: {args.mode.upper()}{RESET}")
    print("-" * 80)
    
    results = []     # Initialize results list for the active phase
    scanner = None   # Initialize scanner to avoid local variable errors
    start_time = time.time()

    try:
        # --- PASSIVE RECONNAISSANCE ---
        if args.passive:
            p_scanner = PassiveScanner(args.domain, logger=logger)
            subdomains = p_scanner.fetch_subdomains(verbose_level=args.verbose)
            
            # Persistence for Passive Phase
            if args.output:
                if hasattr(p_scanner, 'whois_data') and p_scanner.whois_data:
                    reporter.write_intelligence(args.domain, p_scanner.whois_data)
                
                if subdomains:
                    reporter.write_section(f"Passive Subdomains ({args.domain})", subdomains)
        
        # --- WILDCARD DNA ANALYSIS ---
        analyzer = WildcardAnalyzer(target_url=url, logger=logger, timeout=args.timeout)
        w_data = analyzer.check(verbose_level=args.verbose) 
        
        # --- WORDLIST GENERATOR SETUP ---
        wordlist_path, word_count = prepare_wordlist(args.wordlist, logger)
        
        if not wordlist_path:
            sys.exit(1)

        print(f"\n{YELLOW}[*] Initializing wordlist stream...{RESET}")
        word_gen = stream_wordlist(wordlist_path)

        ext_list = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

        # --- ACTIVE SCANNING PHASE ---
        scanner = Scanner(url=url, threads=threads, timeout=args.timeout, wildcard_data=w_data, logger=logger, extensions_arg=ext_list, sf=args.size_filter)
        
        # This will catch the results even if interrupted
        results = scanner.run(word_gen, word_count)

    except UserAbortException:
        # Graceful exit handling for Ctrl+C
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        print(f"\n{RED}[!] Scan aborted by user. Finalizing results...{RESET}")
        
        if scanner:
            results = scanner.results
            if args.output and results:
                reporter.write_section(f"Partial Active Results (Aborted) - {url}", results)

    except Exception as e:
        print(f"\n{RED}[!] Unexpected Error: {e}{RESET}")
        sys.exit(1)

    finally:
        # --- FINALIZATION & PERSISTENCE ---
        duration = time.time() - start_time
        print(f"\n" + "-" * 80)
        print(f"{GREEN}[✓] Scan completed in {duration:.2f}s | Findings: {len(results)}{RESET}")
        
        # Only write final section if it wasn't already handled by an abort
        if args.output and results and scanner and not sys.exc_info()[0]:
            reporter.write_section(f"Active Scan ({url})", results)
    
        print("-" * 80 + "\n")

if __name__ == "__main__":
    main()