#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import pyfiglet
from .colors import CYAN, GREEN, YELLOW, WHITE, RED, RESET, GREY

def show_logo():
    """Prints the ASCII banner and version."""
    ascii_banner = pyfiglet.figlet_format("AIMENRECO")
    print(f"{CYAN}{ascii_banner}{RESET}")
    print(f"{WHITE}v3.2 (Performance) - Advanced Recon & Secret Discovery Framework{RESET}\n")

class ManualHelpParser(argparse.ArgumentParser):
    """Custom help manual with a professional security-tool aesthetic."""
    def print_help(self):
        def fmt_line(short, long, metavar, desc):
            s_part = f"{GREEN}{short}{RESET}" if short else "   "
            comma = f"{WHITE},{RESET} " if short else "  "
            l_part = f"{CYAN}{long}{RESET}"
            m_part = f" {WHITE}{metavar}{RESET}" if metavar else ""
            
            full_flags = f"  {s_part}{comma}{l_part}{m_part}"
            # Precision padding: keeps descriptions perfectly aligned
            padding = " " * (32 - (len(short or "") + len(long) + len(metavar or "") + 4))
            print(f"{full_flags}{padding}{GREY}{desc}{RESET}")

        print(f"{YELLOW}Usage:{RESET} sudo aimenreco -d <domain> -w <wordlist> [options]\n")

        print(f"{YELLOW}REQUIRED ARGUMENTS:{RESET}")
        fmt_line("-d", "--domain"    ,"URL" , "Target domain or URL (e.g., target.com)")
        fmt_line("-w", "--wordlist"  ,"FILE", "Wordlist path or filename in resources")

        print(f"\n{YELLOW}RECON CONFIGURATION:{RESET}")
        fmt_line("-p"   , "--passive"   ,""     , "Enable passive reconnaissance (OSINT via CT Logs)")
        fmt_line("-m"   , "--mode"      ,"MODE" , f"Scan profile: {GREEN}std{RESET} (40 threads) or {RED}aggressive{RESET} (200)")
        fmt_line("-x"   , "--extensions","EXT"  , "Comma-separated extensions (e.g., php,txt,json)")
        fmt_line("-t"   , "--threads"   ,"N"    , "Force a specific number of concurrent threads")
        fmt_line("-q"   , "--quiet"     ,""     , "Only print findings")
        fmt_line("-v"   , "--verbose"    ,""    , "Enable detailed debug and DNA filtering logs")
        fmt_line(""     , "--timeout"    ,"SEC" , "Request timeout in seconds (Default: 5.0)")
        fmt_line("-sf"  , "--size-filter","SIZE", "Manually ignore responses of a specific byte length")
        

        print(f"\n{YELLOW}OUTPUT & DISPLAY:{RESET}")
        fmt_line("-o", "--output", "FILE", "Save successful discoveries to a text file")
        fmt_line("-h", "--help", "", "Show this advanced manual and exit")
        
        print(f"\n{CYAN}Example:{RESET}")
        print(f"  {WHITE}sudo aimenreco -d target.com -w big.txt -p -x php,aspx{RESET}\n")