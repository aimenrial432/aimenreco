import os
from datetime import datetime
from aimenreco.ui.colors import CYAN, RED, RESET

class Reporter:
    """
    Handles the persistence of scan results to the file system.
    
    This class centralizes all write operations, ensuring consistent 
    formatting for both passive OSINT and active scanning results.
    """
    def __init__(self, output_path, logger=None):
        """
        Initializes the Reporter with a destination path.
        
        :param output_path: String path to the output file.
        :param logger: Optional Logger instance for status reporting.
        """
        self.output_path = output_path
        self.logger = logger

    def write_section(self, title, results):
        """
        Writes a formatted section of results to the output file.
        
        :param title: The header title for the section (e.g., 'Passive Recon').
        :param results: List of strings containing the findings.
        """
        if not self.output_path or not results:
            return

        try:
            with open(self.output_path, "a") as f:
                f.write(f"\n{'='*20} {title.upper()} {'='*20}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
                for item in results:
                    f.write(f"{item}\n")
                f.write("-" * 50 + "\n")
            
            if self.logger:
                self.logger.info(f"\n{CYAN}[i] Results for '{title}' saved to {self.output_path}. {RESET} \n")
        except Exception as e:
            if self.logger:
                self.logger.error(f"\n{RED}[!] Failed to write to {self.output_path}: {e}. {RESET}")