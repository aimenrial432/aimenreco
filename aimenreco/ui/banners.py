import argparse
import pyfiglet
import shutil
import re
from .colors import CYAN, GREEN, YELLOW, WHITE, RED, RESET, GREY

def show_logo():
    """Prints the ASCII banner and version."""
    ascii_banner = pyfiglet.figlet_format("AIMENRECO")
    print(f"{CYAN}{ascii_banner}{RESET}")
    print(f"{WHITE}v3.3 (Performance) - Advanced Recon & Secret Discovery Framework{RESET}\n")

class ManualHelpParser(argparse.ArgumentParser):
    """
    Surgical CLI alignment with triple-column anchoring.
    Ensures flags, metavariables, and descriptions are perfectly vertical.
    """

    def print_help(self):
        """Renders the help menu with four fixed tab stops."""
        
        # Fixed Anchors (Offsets)
        long_flag_start = 12       # Where blue flags start
        metavar_start   = 28       # Where white variables (URL, FILE) start
        desc_start      = 45       # Where grey descriptions start

        def clean_ansi(text):
            """Removes ANSI codes for real visible length calculation."""
            return re.sub(r'\x1b\[[0-9;]*m', '', text)

        def fmt_line(short, long, metavar, desc):
            """Formats a line with three padding stages for a grid-like UI."""
            # 1. Short flag block
            s_part = f"{GREEN}{short}{RESET}" if short else "   "
            comma = f"{WHITE},{RESET} " if short else "  "
            prefix = f"  {s_part}{comma}"
            
            # 2. Long flag block
            l_part = f"{CYAN}{long}{RESET}"
            
            # 3. Metavar block
            m_part = f"{WHITE}{metavar}{RESET}" if metavar else ""
            
            # --- Calculations ---
            # Padding 1: From Short to Long
            p1 = " " * (long_flag_start - len(clean_ansi(prefix)))
            
            # Padding 2: From Long to Metavar
            current_str = f"{prefix}{p1}{l_part}"
            p2 = " " * (metavar_start - len(clean_ansi(current_str)))
            
            # Padding 3: From Metavar to Description
            current_str = f"{current_str}{p2}{m_part}"
            p3 = " " * (desc_start - len(clean_ansi(current_str)))
            
            print(f"{current_str}{p3}{GREY}{desc}{RESET}")

        # --- CLI Rendering ---
        print(f"{YELLOW}Usage:{RESET} sudo aimenreco -d <domain> -w <wordlist> [options]\n")

        print(f"{YELLOW}REQUIRED ARGUMENTS:{RESET}")
        fmt_line("-d", "--domain",   "URL",  "Target domain or URL (e.g., target.com)")
        fmt_line("-w", "--wordlist", "FILE", "Wordlist path or filename in resources")

        print(f"\n{YELLOW}RECON CONFIGURATION:{RESET}")
        fmt_line("-V", "--version",    "",     "Shows tools version and exit")
        fmt_line("-p", "--passive",    "",     "Enable passive reconnaissance (OSINT via CT Logs)")
        fmt_line("-m", "--mode",       "MODE", f"Scan profile: {GREEN}std{RESET} or {RED}aggressive{RESET}")
        fmt_line("-x", "--extensions", "EXT",  "Comma-separated extensions (e.g., php,txt,json)")
        fmt_line("-t", "--threads",    "N",    "Force a specific number of concurrent threads")
        fmt_line("-q", "--quiet",      "",     "Only print findings (silences UI noise)")
        fmt_line("-v", "--verbose",    "",     "Enable detailed debug and DNA filtering logs")
        fmt_line("",   "--timeout",    "SEC",  "Request timeout in seconds (Default: 5.0)")
        fmt_line("-sf","--size-filter","SIZE", "Manually ignore responses by byte length")

        print(f"\n{YELLOW}OUTPUT & DISPLAY:{RESET}")
        fmt_line("-o", "--output", "FILE", "Save successful discoveries to a text file")
        fmt_line("-h", "--help",   "",     "Show this advanced manual and exit")
        
        print(f"\n{CYAN}Example:{RESET}")
        print(f"  {WHITE}sudo aimenreco -d target.com -w big.txt -p -x php,aspx{RESET}\n")