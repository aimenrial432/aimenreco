import argparse
import pyfiglet
import shutil
import re
from .colors import CYAN, GREEN, YELLOW, WHITE, RED, RESET, GREY

def show_logo():
    """Prints the ASCII banner and version info to the terminal."""
    ascii_banner = pyfiglet.figlet_format("AIMENRECO")
    print(f"{CYAN}{ascii_banner}{RESET}")
    print(f"{WHITE}v3.3 (Performance) - Advanced Recon & Secret Discovery Framework{RESET}\n")

class ManualHelpParser(argparse.ArgumentParser):
    """
    Custom Help Parser designed for high-readability CLI output.
    Uses anchored columns to keep flags, types, and descriptions aligned.
    """

    def print_help(self):
        """Renders the custom help menu using a fixed grid layout."""
        
        # Column Anchors
        long_flag_start = 12
        metavar_start   = 28
        desc_start      = 45

        def clean_ansi(text):
            """Calculates visible text length by stripping ANSI color codes."""
            return re.sub(r'\x1b\[[0-9;]*m', '', text)

        def fmt_line(short, long, metavar, desc):
            """Formats a single line of the help menu with precise padding."""
            s_part = f"{GREEN}{short}{RESET}" if short else "   "
            comma = f"{WHITE},{RESET} " if short else "  "
            prefix = f"  {s_part}{comma}"
            l_part = f"{CYAN}{long}{RESET}"
            m_part = f"{WHITE}{metavar}{RESET}" if metavar else ""
            
            # Column 1 to Column 2
            p1 = " " * (long_flag_start - len(clean_ansi(prefix)))
            current_str = f"{prefix}{p1}{l_part}"
            
            # Column 2 to Column 3
            p2 = " " * (metavar_start - len(clean_ansi(current_str)))
            current_str = f"{current_str}{p2}{m_part}"
            
            # Column 3 to Description
            p3 = " " * (desc_start - len(clean_ansi(current_str)))
            
            print(f"{current_str}{p3}{GREY}{desc}{RESET}")

        # Render Header
        print(f"{YELLOW}Usage:{RESET} aimenreco -d <domain> [options]\n")

        print(f"{YELLOW}CORE ARGUMENTS:{RESET}")
        fmt_line("-d", "--domain",    "URL",   "Target domain or URL (e.g., target.com)")
        fmt_line("-w", "--wordlist",  "FILE",  "Dictionary for active discovery (Enables Active Scan)")

        print(f"\n{YELLOW}RECON CONFIGURATION:{RESET}")
        fmt_line("-V", "--version",    "",      "Show program version and exit")
        fmt_line("-p", "--passive",    "",      "Enable passive OSINT via Certificate Transparency")
        fmt_line("-m", "--mode",       "MODE",  f"Scan profile: {GREEN}std{RESET} or {RED}aggressive{RESET}")
        fmt_line("-x", "--extensions", "EXT",   "Comma-separated list (e.g., php,txt,json)")
        fmt_line("-t", "--threads",    "N",      "Manual thread override")
        fmt_line("-q", "--quiet",      "",      "Suppress UI overhead (Only show findings)")
        fmt_line("-v", "--verbose",    "",      "Enable DNA filtering and debug logs")
        fmt_line("",   "--timeout",    "SEC",   "Network request timeout (Default: 5.0)")
        fmt_line("-sf","--size-filter","SIZE",  "Ignore responses by exact byte length")

        print(f"\n{YELLOW}OUTPUT & DISPLAY:{RESET}")
        fmt_line("-o", "--output",     "FILE",  "Export findings to a text file")
        fmt_line("-h", "--help",       "",      "Show this professional manual and exit")
        
        print(f"\n{CYAN}Examples:{RESET}")
        print(f"  {WHITE}aimenreco -d target.com -p{RESET} (Passive OSINT - No root required)")
        print(f"  {WHITE}sudo aimenreco -d target.com -w big.txt -x php{RESET} (Full Active Scan)\n")