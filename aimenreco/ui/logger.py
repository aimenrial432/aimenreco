import sys
from aimenreco.ui.colors import *

class Logger:
    def __init__(self, quiet=False, verbose=0):
        self.quiet = quiet
        self.verbose = verbose 
        
    def _display(self, message):
        """Helper, only display a message if quiet mode is not activated"""
        #if not self.quiet:
        print(message)
            
    def process(self, message, color=YELLOW):
        """Displays messgaes about ejecution for example (Gathering WHOIS intelligence for...)"""
        self._display(f"{color}[*] {message}{RESET}")
        
    def title(self, message):
        """Displays messgaes for titles on the tool"""
        self._display(f"{message}")

    def info(self, message, color=BLUE):
        """Displays general informative messagges: [i] Info..."""
        self._display(f"{color}[i] {message}{RESET}")
        
    def success(self, message):
        """Displays messages for completed checkpoints: [✓] Hecho."""
        self._display(f"{GREEN}[✓] {message}{RESET}")
        
    def result(self, message, color=WHITE):
        """Displays a direct result (Without prefixes)."""
        self._display(f"{color}{message}{RESET}")
        
    def saved(self, message, color=WHITE):
        """Displays a message for saves."""
        self._display(f"{CYAN}[i] {message}{RESET}")
        
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

    def warn(self, message):
        self._display(f"{YELLOW}[!] Warning: {message}{RESET}")
            
    def error(self, message):
        #Error messagges always shoul be displayed
        print(f"{RED}[!] Error: {message}{RESET}")
            
    def status(self, message, flush=True):
        if not self.quiet:
            sys.stdout.write(message)
            if flush:
                sys.stdout.flush()