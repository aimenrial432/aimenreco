#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
import argparse
import signal
from typing import List, Optional, Tuple, Generator, Any, Union

from aimenreco.ui.banners import ManualHelpParser, show_logo
from aimenreco.ui.colors import CYAN, WHITE, GREEN, RED, BLUE, YELLOW, RESET, PURPLE
from aimenreco.utils.helpers import clean_url, stream_wordlist, prepare_wordlist, get_resource_path
from aimenreco.core.wildcard import WildcardAnalyzer 
from aimenreco.core.scanner import Scanner
from aimenreco.core.passive import PassiveScanner
from aimenreco.ui.logger import Logger
from aimenreco.utils.reporter import Reporter
from aimenreco.utils.exceptions import UserAbortException
from aimenreco.models import WildcardDNA

from aimenreco import __version__

def signal_handler(sig: int, frame: Any) -> None:
    """
    Handles keyboard interrupts (SIGINT) to ensure graceful shutdown.
    
    Args:
        sig (int): Signal number.
        frame (Any): Current stack frame.
    """
    raise UserAbortException()

def check_privileges(logger: Logger) -> None:
    """
    Ensures the process has administrative privileges.
    Required for high-performance socket operations and active scanning.
    
    Args:
        logger (Logger): Logger instance for error reporting.
    """
    if os.geteuid() != 0:
        logger.error(f"This operation requires root privileges.{RESET}")
        logger.title(f"{YELLOW}Hint: Run the command using {RESET}{WHITE}'sudo aimenreco ...'{RESET}\n")
        sys.exit(1)

def main() -> None:
    """
    Aimenreco CLI Orchestrator.
    Handles mode selection, privilege checks, and scanning lifecycle management.
    """

    # --- PHASE 0: ARGUMENT DEFINITION ---
    parser = ManualHelpParser(add_help=False)
    parser.add_argument('-V', '--version', action='store_true', help="Show version and logo")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Dictionary path")
    parser.add_argument("-m", "--mode", default=None, choices=["std", "aggressive"], help="Scan profile")
    parser.add_argument("-bf", "--brute-force", action="store_true", help="Force brute-force profile")
    parser.add_argument("-x", "--extensions", default="", help="File extensions")
    parser.add_argument("-t", "--threads", type=int, help="Thread count override")
    parser.add_argument("--timeout", type=float, help="Network timeout override")
    parser.add_argument("-o", "--output", help="Output report file")
    parser.add_argument("-h", "--help", action="store_true", help="Show help manual")
    parser.add_argument("-p", "--passive", action="store_true", help="Enable passive OSINT")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimalist output")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level")
    parser.add_argument("-sf", "--size-filter", type=str, help="Filter by response size")
    
    args: argparse.Namespace
    args, _ = parser.parse_known_args()
    
    # Initialize Logger early to handle all output
    logger: Logger = Logger(quiet=args.quiet, verbose=args.verbose)

    # --- PHASE 1: PUBLIC FLAGS ---
    if args.version:
        show_logo()
        logger.info(f"High-performance endpoint reconnaissance & DNA analysis.{RESET}\n")
        sys.exit(0)

    if args.help:
        show_logo()
        parser.print_help()
        sys.exit(0)

    # --- PHASE 2: TARGET & PRIVILEGE VALIDATION ---
    if not args.domain:
        show_logo()
        parser.print_help()
        logger.error(f"\nError: Target domain (-d) is required.{RESET}\n")
        sys.exit(1)

    check_privileges(logger)

    # --- PHASE 3: INTELLIGENT ENGINE SETUP ---
    is_brute_base: bool = args.brute_force or args.mode == "aggressive"
    
    default_threads: int = 200 if is_brute_base else 40
    default_timeout: float = 1.0 if is_brute_base else 3.0
    
    is_custom: bool = args.threads is not None or args.timeout is not None
    
    threads: int = args.threads if args.threads is not None else default_threads
    actual_timeout: float = args.timeout if args.timeout is not None else default_timeout
    
    # UI Labeling
    mode_label: str = f"{YELLOW}CUSTOM{RESET}" if is_custom else \
                      f"{RED}BRUTE-FORCE{RESET}" if is_brute_base else f"{GREEN}STD{RESET}"

    if not args.wordlist:
        args.wordlist = get_resource_path("combined_directories.txt" if is_brute_base else "common.txt")

    # --- PHASE 4: INITIALIZATION ---
    signal.signal(signal.SIGINT, signal_handler)
    reporter: Reporter = Reporter(args.output, logger=logger)
    
    show_logo()
    if not args.quiet:
        logger.title(f"{BLUE}Engine Strategy Summary:{RESET}")
        logger.tree("Target Domain", args.domain, color=PURPLE)
        logger.tree("Execution Mode", mode_label)
        logger.tree("Concurrency", f"{threads} threads", color=YELLOW)
        logger.tree("Network Delay", f"{actual_timeout}s timeout", color=YELLOW)
        logger.tree("Payload Source", os.path.basename(args.wordlist), color=CYAN)
        print("-" * 45 + "\n")

    url: str = clean_url(args.domain)
    start_time: float = time.time()
    results: List[Any] = []
    subdomains: List[str] = []
    scanner: Optional[Scanner] = None

    try:
        # --- PHASE 5: RECONNAISSANCE LIFECYCLE ---
        if args.passive:
            p_scanner: PassiveScanner = PassiveScanner(args.domain, logger=logger)
            subdomains = p_scanner.fetch_subdomains(verbose_level=args.verbose)

        # Active Discovery (Default Behavior)
        analyzer: WildcardAnalyzer = WildcardAnalyzer(target_url=url, logger=logger, timeout=int(actual_timeout))
        
        # FIX: Handle potential tuple return from legacy analyzer.check
        w_data_raw: Any = analyzer.check(verbose_level=args.verbose) 
        w_data: WildcardDNA = WildcardDNA(*w_data_raw) if isinstance(w_data_raw, tuple) else w_data_raw
        
        wordlist_info: Tuple[Optional[str], int] = prepare_wordlist(args.wordlist, logger)
        wordlist_path: Optional[str] = wordlist_info[0]
        word_count: int = wordlist_info[1]
        
        if not wordlist_path: 
            sys.exit(1)

        # FIX: Allow word_gen to be Optional to prevent type incompatibility with None
        word_gen: Optional[Generator[str, Any, None]] = stream_wordlist(wordlist_path)
        
        if word_gen is None:
            logger.error("Failed to initialize wordlist generator.")
            sys.exit(1)

        ext_list: Optional[List[str]] = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

        scanner = Scanner(
            url=url, threads=threads, timeout=actual_timeout, 
            wildcard_data=w_data, logger=logger, 
            extensions_arg=ext_list, sf=args.size_filter
        )
        
        results = scanner.run(word_gen, word_count)

    except UserAbortException:
        sys.stdout.write("\r" + " " * 80 + "\r")
        logger.warn(f"Scan aborted by user. Cleaning hooks...")
        if scanner: 
            results = scanner.results

    except Exception as e:
        logger.error(f"Critical framework failure: {e}")
        if args.verbose > 0:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    finally:
        # --- PHASE 6: FINAL CONSOLIDATION ---
        duration: float = time.time() - start_time
        print(f"\n" + "-" * 80)
        if subdomains:
            logger.success(f"OSINT Intelligence: {len(subdomains)} subdomains mapped.")
        if results:
            logger.success(f"Active Discovery: {len(results)} endpoints identified.")
            if args.output:
                reporter.write_section(f"Final Discovery Report ({url})", results)
        
        logger.info(f"Reco completed in {duration:.2f} seconds.")
        print("-" * 80 + "\n")

if __name__ == "__main__":
    main()