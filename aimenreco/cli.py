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
from aimenreco.core.intel import TechAnalyzer
from aimenreco.ui.logger import Logger
from aimenreco.utils.reporter import Reporter
from aimenreco.utils.exceptions import UserAbortException
from aimenreco import __version__

def signal_handler(sig, frame):
    """
    Handles SIGINT (Ctrl+C) by raising a custom exception.
    Allows the framework to catch the interrupt and perform graceful cleanup.
    """
    raise UserAbortException()

def check_privileges(domain, wordlist):
    """
    Validates process privileges for active scanning modules.
    Exits if root is missing when an active scan is requested.
    """
    if os.geteuid() != 0:
        show_logo()
        print(f"{RED}[!] Error: Active scanning modules require root privileges.{RESET}")
        print(f"{YELLOW}[i] Execution Tip: sudo aimenreco -d {domain} -w {wordlist}{RESET}\n")
        sys.exit(1)

def main():
    """
    Main entry point for the Aimenreco Discovery Framework.
    
    Workflow Orchestration:
    1. Argument parsing and non-privileged operations (Help/Version).
    2. Context validation: Determines if the scan is Passive-only or Active.
    3. Privilege validation: Only enforces root for Active phases.
    4. Execution: Runs Passive OSINT followed by Active DNA & Enumeration if requested.
    """

    # --- PHASE 0: ARGUMENT PARSING ---
    parser = ManualHelpParser(add_help=False)
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}', help="Show version")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Wordlist path")
    parser.add_argument("-m", "--mode", default="std", help="Scan profile")
    parser.add_argument("-x", "--extensions", default="", help="Extensions")
    parser.add_argument("-t", "--threads", type=int, help="Thread count")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    parser.add_argument("-p", "--passive", action="store_true", help="Passive mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity")
    parser.add_argument("-sf", "--size-filter", type=str, help="Size filter")
    
    args, unknown = parser.parse_known_args()

    # --- PUBLIC OPERATIONS ---
    if args.help:
        show_logo()
        parser.print_help()
        sys.exit(0)

    # --- CONTEXT VALIDATION ---
    if not args.domain:
        show_logo()
        parser.print_help()
        sys.exit(1)

    is_active_mode = bool(args.wordlist)
    
    if is_active_mode:
        check_privileges(args.domain, args.wordlist)

    if not args.passive and not is_active_mode:
        show_logo()
        print(f"{RED}[!] Error: No scan action specified.{RESET}")
        print(f"{YELLOW}[i] Use '-p' for passive recon or '-w' for active enumeration.{RESET}\n")
        sys.exit(1)

    # --- INITIALIZATION ---
    signal.signal(signal.SIGINT, signal_handler)
    logger = Logger(quiet=args.quiet, verbose=args.verbose)
    reporter = Reporter(args.output, logger=logger)
    show_logo()
        
    url = clean_url(args.domain)
    start_time = time.time()
    results = []
    subdomains = []
    scanner = None

    try:
       # --- PHASE 1: PASSIVE RECONNAISSANCE ---
        if args.passive:
            p_scanner = PassiveScanner(args.domain, logger=logger)
            
            # This single call now handles Tech -> WHOIS -> Subdomains in order
            subdomains = p_scanner.fetch_subdomains(verbose_level=args.verbose)
            
            # Get the data already collected by the scanner
            technologies = p_scanner.tech_stack
            whois_data = p_scanner.whois_data

            if args.output:
                # 1. Write WHOIS
                if whois_data:
                    reporter.write_intelligence(args.domain, whois_data)
                
                # 2. Write Tech (Only if found)
                if technologies:
                    reporter.write_section(f"Technology Stack ({args.domain})", technologies)

                # 3. Write Subdomains (Only if found)
                if subdomains:
                    reporter.write_section(f"Passive Subdomains ({args.domain})", subdomains)
                    
                logger.info(f"{CYAN}[i] All passive intelligence saved to {WHITE}{args.output}{RESET}.")
                    
        # --- PHASE 2: ACTIVE SCANNING ---
        if is_active_mode:
            analyzer = WildcardAnalyzer(target_url=url, logger=logger, timeout=args.timeout)
            w_data = analyzer.check(verbose_level=args.verbose) 
            
            wordlist_path, word_count = prepare_wordlist(args.wordlist, logger)
            if not wordlist_path: sys.exit(1)

            print(f"\n{YELLOW}[*] Initializing wordlist stream...{RESET}")
            word_gen = stream_wordlist(wordlist_path)

            threads = args.threads or (200 if args.mode == "aggressive" else 40)
            ext_list = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

            scanner = Scanner(
                url=url, threads=threads, timeout=args.timeout, 
                wildcard_data=w_data, logger=logger, 
                extensions_arg=ext_list, sf=args.size_filter
            )
            
            results = scanner.run(word_gen, word_count)
        else:
            print(f"\n{BLUE}[i] Passive recon finished. Skipping active phase (no wordlist).{RESET}")

    except UserAbortException:
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"\n{RED}[!] Aborted by user. Finalizing...{RESET}")
        if scanner:
            results = scanner.results
            if args.output and results:
                reporter.write_section(f"Partial Results (Aborted) - {url}", results)

    except Exception as e:
        print(f"\n{RED}[!] Framework Error: {e}{RESET}")
        sys.exit(1)

    finally:
        total_findings_passive = len(subdomains) if 'subdomains' in locals() else 0
        duration = time.time() - start_time
        print(f"\n" + "-" * 80)
        
        print(f"{GREEN}[✓] Task finished in {duration:.2f}s | Active Findings: {len(results)}{RESET}")
        print(f"{GREEN}[✓] Task finished in {duration:.2f}s | Passive findings: {total_findings_passive}{RESET}")
        
        # Final output write for active findings
        if args.output and results and scanner and not sys.exc_info()[0]:
            reporter.write_section(f"Active Results ({url})", results)
        print("-" * 80 + "\n")

if __name__ == "__main__":
    main()