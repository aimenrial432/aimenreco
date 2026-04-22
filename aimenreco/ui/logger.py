import sys
from typing import Any
from aimenreco.ui.colors import *

class Logger:
    def __init__(self, quiet: bool = False, verbose: int = 0) -> None:
        """
        Initializes the logger with quiet and verbosity settings.
        
        Args:
            quiet (bool): If True, suppresses non-error output.
            verbose (int): Verbosity level (0 to 3).
        """
        self.quiet: bool = quiet
        self.verbose: int = verbose 
        
    def _display(self, message: str) -> None:
        """Helper, only display a message if quiet mode is not activated"""
        if not self.quiet:
            print(message)
            
    def process(self, message: str, color: str = YELLOW) -> None:
        """Displays messages about execution (e.g., 'Gathering WHOIS...')"""
        self._display(f"{color}[*] {message}{RESET}")
        
    def title(self, message: str) -> None:
        """Displays messages for titles on the tool"""
        self._display(f"{message}")

    def info(self, message: str, color: str = BLUE) -> None:
        """Displays general informative messages: [i] Info..."""
        self._display(f"{color}[i] {message}{RESET}")
        
    def success(self, message: str) -> None:
        """Displays messages for completed checkpoints: [✓] Hecho."""
        self._display(f"{GREEN}[✓] {message}{RESET}")
        
    def result(self, message: str, color: str = WHITE) -> None:
        """Displays a direct result (Without prefixes)."""
        self._display(f"{color}{message}{RESET}")
        
    def saved(self, message: str, color: str = WHITE) -> None:
        """Displays a message for saves."""
        self._display(f"{CYAN}[i] {message}{RESET}")
        
    def v(self, message: str, level: int = 1) -> None:
        """
        Prints messages based on verbosity level.
        -v   -> level 1
        -vv  -> level 2
        -vvv -> level 3
        """
        if not self.quiet and self.verbose >= level:
            print(message)

    def tree(self, label: str, value: Any, color: str = WHITE, is_last: bool = False) -> None:
        """
        Helper to print consistent tree structures.
        
        Args:
            label (str): The key or name of the attribute.
            value (Any): The value to display (can be any type).
            color (str): Color for the value text.
            is_last (bool): If True, uses the 'end of branch' connector.
        """
        if self.quiet:
            return
        connector: str = f"{PURPLE}└─{RESET}" if is_last else f"{PURPLE}├─{RESET}"
        print(f"   {connector} {WHITE}{label}:{RESET} {color}{value}{RESET}")

    def warn(self, message: str) -> None:
        """Displays a warning message."""
        self._display(f"{YELLOW}[!] Warning: {message}{RESET}")
            
    def error(self, message: str) -> None:
        """Error messages should always be displayed regardless of quiet mode."""
        print(f"{RED}[!] Error: {message}{RESET}")
            
    def status(self, message: str, flush: bool = True) -> None:
        """Prints a status message without a newline, useful for progress bars."""
        if not self.quiet:
            sys.stdout.write(message)
            if flush:
                sys.stdout.flush()