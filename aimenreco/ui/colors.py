#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
aimenreco UI - Terminal Color Palette
-------------------------------------
This module defines the visual identity of aimenreco v3.2
Provides ANSI escape codes and semantic mapping for UI consistency.

Author: Oier Garcia
"""

# --- BASE ANSI CODES ---
# Define base colors used to construct the terminal interface
GREEN  = "\033[1;32m"  # Success (Found directories/subdomains)
RED    = "\033[1;31m"  # Errors (404s, Timeouts, Network failures)
YELLOW = "\033[1;33m"  # Warnings (Wildcard detection, Interruptions)
BLUE   = "\033[1;34m"  # Informational (Thread config, Wordlist loading)
CYAN   = "\033[1;36m"  # Aesthetics (Banners and section headers)
WHITE  = "\033[1;37m"  # Highlighting (URLs, found paths)
GREY   = "\033[1;90m"  # Secondary details (Progress bars, thread IDs)
PURPLE = "\033[1;35m"  # OSINT & Special discovery (WHOIS/Cloudflare)
RESET  = "\033[0m"     # Global Reset (Essential to prevent color bleeding)

# --- SEMANTIC MAPPING ---
# Centralizes the logic: changing a color here updates the entire framework.
CLR_SUCCESS = GREEN
CLR_ERROR   = RED
CLR_WARN    = YELLOW
CLR_INFO    = CYAN
CLR_PATH    = WHITE
CLR_METRIC  = GREY
CLR_OSINT = PURPLE

# --- MESSAGING PRESETS ---
# Pre-formatted status tags to maintain UI consistency across modules.
# Usage: print(f"{MSG_FOUND} {url}")
MSG_FOUND = f"{WHITE}[{GREEN}+{WHITE}]{RESET}"
MSG_ERROR = f"{WHITE}[{RED}!{WHITE}]{RESET}"
MSG_INFO  = f"{WHITE}[{CYAN}i{WHITE}]{RESET}"
MSG_WAIT  = f"{WHITE}[{YELLOW}*{WHITE}]{RESET}"
MSG_STEP  = f"{GREY}[{WHITE}#{GREY}]{RESET}"
MSG_OSINT = f"{WHITE}[{PURPLE}@{WHITE}]{RESET}"