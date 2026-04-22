#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
aimenreco UI - Terminal Color Palette
-------------------------------------
This module defines the visual identity of Aimenreco.
Provides ANSI escape codes and semantic mapping for UI consistency.

Author: Oier Garcia
"""

# --- BASE ANSI CODES ---
# Explicitly typing as str for IDE consistency
GREEN: str  = "\033[1;32m"  # Success (Found directories/subdomains)
RED: str    = "\033[1;31m"  # Errors (404s, Timeouts, Network failures)
YELLOW: str = "\033[1;33m"  # Warnings (Wildcard detection, Interruptions)
BLUE: str   = "\033[1;34m"  # Informational (Thread config, Wordlist loading)
CYAN: str   = "\033[1;36m"  # Aesthetics (Banners and section headers)
WHITE: str  = "\033[1;37m"  # Highlighting (URLs, found paths)
GREY: str   = "\033[1;90m"  # Secondary details (Progress bars, timestamps)
PURPLE: str = "\033[1;35m"  # OSINT & Special discovery (WHOIS/DNS)
RESET: str  = "\033[0m"     # Global Reset (Prevents color bleeding)

# --- SEMANTIC MAPPING ---
# Centralizes the visual logic for the entire framework
CLR_SUCCESS: str = GREEN
CLR_ERROR: str   = RED
CLR_WARN: str    = YELLOW
CLR_INFO: str    = CYAN
CLR_PATH: str    = WHITE
CLR_METRIC: str  = GREY
CLR_OSINT: str   = PURPLE

# --- MESSAGING PRESETS ---
# Pre-formatted status tags for consistent status reporting
# Usage: print(f"{MSG_FOUND} {url}")
MSG_FOUND: str = f"{WHITE}[{GREEN}+{WHITE}]{RESET}"
MSG_ERROR: str = f"{WHITE}[{RED}!{WHITE}]{RESET}"
MSG_INFO: str  = f"{WHITE}[{CYAN}i{WHITE}]{RESET}"
MSG_WAIT: str  = f"{WHITE}[{YELLOW}*{WHITE}]{RESET}"
MSG_STEP: str  = f"{GREY}[{WHITE}#{GREY}]{RESET}"
MSG_OSINT: str = f"{WHITE}[{PURPLE}@{WHITE}]{RESET}"

def strip_colors(text: str) -> str:
    """
    Utility to remove ANSI codes from a string.
    Useful for logging to files where raw escape codes are unwanted.
    """
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)