import sys
from aimenreco.ui.colors import RESET, WHITE, YELLOW, RED

class Logger:
    def __init__(self, quiet=False, verbose=False):
        self.quiet = quiet
        self.verbose = verbose

    def info(self, message):
        """Messages for the default level (Banners, status)"""
        if not self.quiet:
            print(message)

    def success(self, message):
        """Findings - ALWAYS printed unless it's a very specific raw mode"""
        print(message)

    def debug(self, message):
        """Technical details for Verbose mode"""
        if self.verbose and not self.quiet:
            print(f"{WHITE}[DEBUG] {message}{RESET}")

    def warn(self, message):
        if not self.quiet:
            print(f"{YELLOW}[!] {message}{RESET}")
            
    def error(self, message):
            print(f"{RED}[!] {message}{RESET}")
            
    def status(self, message, flush=True):
        """
        Progress and count: Optimized for terminal rewriting.
        Uses stdout.write to allow the '\r' carriage return to work.
        """
        sys.stdout.write(message)
        if flush:
            sys.stdout.flush()