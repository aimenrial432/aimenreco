import sys
from aimenreco.ui.colors import RESET, WHITE, YELLOW, RED, PURPLE, GREY

class Logger:
    def __init__(self, quiet=False, verbose=0):
        self.quiet = quiet
        self.verbose = verbose  # Ahora es un int (0, 1, 2, 3)

    def info(self, message):
        """Standard progress messages."""
        if not self.quiet:
            print(message)

    def v(self, message, level=1):
        """
        Prints messages based on verbosity level.
        -v   -> level 1
        -vv  -> level 2
        -vvv -> level 3
        """
        if not self.quiet and self.verbose >= level:
            print(message)

    def tree(self, label, value, color=WHITE, is_last=False):
        """Helper to print consistent tree structures."""
        if self.quiet:
            return
        connector = f"{PURPLE}└─{RESET}" if is_last else f"{PURPLE}├─{RESET}"
        print(f"   {connector} {WHITE}{label}:{RESET} {color}{value}{RESET}")

    def success(self, message):
        print(message)

    def warn(self, message):
        if not self.quiet:
            print(f"{YELLOW}[!] {message}{RESET}")
            
    def error(self, message):
        print(f"{RED}[!] {message}{RESET}")
            
    def status(self, message, flush=True):
        if not self.quiet:
            sys.stdout.write(message)
            if flush:
                sys.stdout.flush()