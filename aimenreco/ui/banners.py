#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import pyfiglet # type: ignore
import shutil
import re
from typing import Optional, Any

from .colors import CYAN, GREEN, YELLOW, WHITE, RED, RESET, GREY
from .logger import Logger

# Instance for internal module use
logger: Logger = Logger()

def show_logo() -> None:
    """
    Prints the ASCII banner and version info to the terminal.
    """
    ascii_banner: str = pyfiglet.figlet_format("AIMENRECO")
    logger.title(f"{CYAN}{ascii_banner}{RESET}")
    logger.title(f"{WHITE}v3.3 (Performance) - Advanced Recon & Secret Discovery Framework{RESET}\n")

class ManualHelpParser(argparse.ArgumentParser):
    """
    Custom Help Parser designed for high-readability CLI output.
    Uses anchored columns to keep flags, types, and descriptions aligned.
    """

    def print_help(self, file: Optional[Any] = None) -> None:
        """
        Renders the custom help menu using a fixed grid layout.
        
        Args:
            file: Argument required by the argparse protocol (not used here).
        """
        
        # Column Anchors
        long_flag_start: int = 12
        metavar_start: int = 28
        desc_start: int = 45

        def clean_ansi(text: str) -> str:
            """Calculates visible text length by stripping ANSI color codes."""
            return re.sub(r'\x1b\[[0-9;]*m', '', text)

        def fmt_line(short: str, long: str, metavar: str, desc: str) -> None:
            """
            Formats a single line of the help menu with precise padding.
            
            Args:
                short: Short flag (e.g., '-d').
                long: Long flag (e.g., '--domain').
                metavar: Variable placeholder (e.g., 'URL').
                desc: Argument description.
            """
            s_part: str = f"{GREEN}{short}{RESET}" if short else "   "
            comma: str = f"{WHITE},{RESET} " if short else "  "
            prefix: str = f"  {s_part}{comma}"
            l_part: str = f"{CYAN}{long}{RESET}"
            m_part: str = f"{WHITE}{metavar}{RESET}" if metavar else ""
            
            # Column 1 to Column 2
            p1: str = " " * (long_flag_start - len(clean_ansi(prefix)))
            current_str: str = f"{prefix}{p1}{l_part}"
            
            # Column 2 to Column 3
            p2: str = " " * (metavar_start - len(clean_ansi(current_str)))
            current_str = f"{current_str}{p2}{m_part}"
            
            # Column 3 to Description
            p3: str = " " * (desc_start - len(clean_ansi(current_str)))
            
            print(f"{current_str}{p3}{GREY}{desc}{RESET}")

        # Render Header
        logger.title(f"{YELLOW}Usage:{RESET}{GREY} aimenreco -d <domain> [options]{RESET}\n")

        logger.title(f"{YELLOW}CORE ARGUMENTS:{RESET}")
        fmt_line("-d", "--domain",    "URL",   "Target domain or URL (e.g., target.com)")
        fmt_line("-w", "--wordlist",  "FILE",  "Dictionary for active discovery (Enables Active Scan)")

        logger.title(f"\n{YELLOW}RECON CONFIGURATION:{RESET}")
        fmt_line("-V",  "--version",     "",      "Show program version and exit")
        fmt_line("-p",  "--passive",     "",      "Enable passive OSINT via Certificate Transparency")
        fmt_line("-m",  "--mode",        "MODE",  f"Scan profile: {GREEN}std{RESET} or {RED}aggressive{RESET}")
        fmt_line("-bf", "--brute-force", "",      "Helper flag for a brute force scan")
        fmt_line("-x",  "--extensions",  "EXT",   "Comma-separated list (e.g., php,txt,json)")
        fmt_line("-t",  "--threads",     "N",      "Manual thread override")
        fmt_line("-q",  "--quiet",       "",      "Suppress UI overhead (Only show findings)")
        fmt_line("-v",  "--verbose",     "",      "Enable DNA filtering and debug logs")
        fmt_line("",    "--timeout",     "SEC",   "Network request timeout (Default: 5.0)")
        fmt_line("-sf", "--size-filter", "SIZE",  "Ignore responses by exact byte length")

        logger.title(f"\n{YELLOW}OUTPUT & DISPLAY:{RESET}")
        fmt_line("-o", "--output",     "FILE",  "Export findings to a text file")
        fmt_line("-h", "--help",       "",      "Show this professional manual and exit")
        
        logger.title(f"\n{YELLOW}Examples:{RESET}")
        logger.info(f"Only root privileges can activate the scan.{RESET}")
        logger.title(f"{WHITE}aimenreco -d target.com -p{RESET}")
        logger.title(f"{WHITE}sudo aimenreco -d target.com -w big.txt -x php -p{RESET} (Full Active Scan)\n")