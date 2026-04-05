# 🛡️ Aimenreco v3.2 (Performance & Modular Engine dev phase)

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/category-Pentesting-red)
![Status](https://img.shields.io/badge/status-Development--Branch-orange)
![Build Status](https://github.com/aimenrial432/aimenreco/actions/workflows/tests.yml/badge.svg)

```text
    _   ___ __  __ _____ _   _ ____  _____ ____ ___
   / \ |_ _|  \/  | ____| \ | |  _ \| ____/ ___/ _ \
  / _ \ | || |\/| |  _| |  \| | |_) |  _|| |  | | | |
 / ___ \| || |  | | |___| |\  |  _ <| |__| |__| |_| |
/_/   \_\___|_|  |_|_____|_| \_|_| \_\_____\____\___/


Aimenreco is an advanced reconnaissance and asset discovery framework designed for security auditors. Unlike traditional fuzzers, Aimenreco combines Passive Intelligence (OSINT) with a high-performance active enumeration engine.

⚠️ NOTE: This tool is currently in active development. New features and engine optimizations are being added constantly.
⚠️ NOTE: You are on the dev branch. This version includes the new modular engine and passive reconnaissance functions.


🚀 Key Features

🔍 Passive Recon (Enhanced): Automated subdomain discovery via SSL/TLS (crt.sh) with intelligent fallback to HackerTarget API. Transparency logs with real-time tree-view visualization.

🛡️ Tech Profiling (New): Deep fingerprinting using WhatWeb (if available), Favicon MD5 hashing, and HTTP header analysis (Server, X-Powered-By) to identify CMS and frameworks.

🌐 Domain Intelligence: Integrated WHOIS analyzer with auto-retry logic to extract register, expiration dates, and nameservers.

🧬 Wildcard DNA DNA Filtering: Intelligent detection of DNS/HTTP wildcards. It analyzes "server fingerprints" to eliminate false positives, even with dynamic 301/302 redirects.

⚡ Memory-Safe Engine: Optimized using asyncio.BoundedSemaphore and Python generators to process massive wordlists (1M+ lines) with minimal RAM footprint.

🎨 Professional UI: Clean interface with dynamic progress bars and real-time findings.

🕵️ Stealth Rotation: Built-in User-Agent rotation from shared JSON resources to bypass basic WAF fingerprinting.

📦 Modular & Portable: Standard package structure for clean, global installation on Linux systems.

🔍 How It Works (The Intelligence Layer)
Aimenreco is not a "blind" brute-force fuzzer. It employs a strategic three-layer reconnaissance approach to maximize discovery while minimizing noise:
    -Layer 0: Technology Fingerprinting
        Before scanning, Aimenreco fingerprints the target's stack. It identifies CMS (WordPress, Drupal), Web Servers (Nginx, Apache), and Frameworks (Express, PHP) to give context to the findings.

    -Layer 1: OSINT Certificate Transparency
        The passive module queries CT logs and HackerTarget API to discover subdomains that might not be listed in public DNS but have issued SSL certificates.

    -Layer 2: Network DNA Fingerprinting
        Performs a 10-point stress test against the target to create a unique DNA Profile based on:
            HTTP Status: Detects universal redirects (301/302).
            Content Hashing (MD5)**: Identifies custom error pages.
            Size Variance: Establishes a byte-threshold to distinguish noise.

    -Layer 3: Smart Enumeration
        Filters noise in real-time using the DNA profile, ensuring zero false positives even on complex "catch-all" servers.

🛠️ Installation & Setup
    1. Clone and Dependencies

        git clone [https://github.com/aimenrial432/aimenreco.git](https://github.com/aimenrial432/aimenreco.git)
        cd aimenreco
        git checkout dev
        pip install -r requirements.txt

    2. System Installation (Recommended)

        Install in editable mode to run aimenreco from any path:
            sudo pip install -e . --break-system-packages

📖 Usage Guide

    sudo aimenreco -d <DOMAIN> -w <WORDLIST> [OPTIONS]

    Options:
        -d,  --domain: Target domain (e.g., target.com).
        -w,  --wordlist: Path to wordlist.
        -p,  --passive: (New) Enable passive subdomain discovery.
        -m,  --mode: Scan mode (std or aggressive).
        -x,  --extensions: Comma-separated list of extensions (e.g., php,txt,html).
        -o,  --output: Save results to a file.
        -q,  --quiet: Scan without showing all data on console. Only results will appear
        -sF, --size-filter: Manually ignore responses by bytes length (You can put more than one -sF x,y,z)
        -v,  --verbose: Scan with data in the console. Diferent data levels -v, -vv and debug mode -vvv


💡 Usage Examples

    Basic scan:
        sudo aimenreco -d target.com -w common.txt

    Full Recon (Passive + Active):
        sudo aimenreco -d target.com -w common.txt -p

    Full Recon (Passive + Active + Quiet or verbose):
        sudo aimenreco -d target.com -w common.txt -p -q/v

    Aggressive Scan with Extensions:
        sudo aimenreco -d target.com -w common.txt -m aggressive -x php,conf,bak

🧪 Testing & Quality Assurance
    Aimenreco includes a comprehensive test suite powered by pytest and pytest-mock to ensure engine stability and detection accuracy. The suite currently features 29+ automated tests covering edge cases and failover scenarios.

    Current Test Coverage:
        - DNA Engine (`test_dna.py`): Validates the statistical profiling logic and ensures the 80% consistency threshold works on 2xx/3xx/4xx responses.

        - Passive Discovery (`test_passive.py`): Tests the crt.sh parser and the exponential backoff resilience.
            - New: Validates fallback logic to HackerTarget API when primary OSINT sources fail.
            - New: Verifies technology fingerprinting (WhatWeb integration, Favicon MD5 hashing, and Header analysis).

        - Intelligence Metadata (test_whois.py): Ensures WHOIS data extraction (registrar, dates) is accurate and handles connection retries gracefully.

        - Scanner Core (`test_scanner.py`): Validates multi-threading safety, asynchronous execution, and result filtering.

        - Reporting System (test_reporter.py): Verifies the integrity of output files (JSON/TXT) and ensures data persistence.

        - Utility & Logic (test_helpers.py): Ensures URL normalization, domain cleaning, and resource loading are path-independent and OS-agnostic.

    Running the Suite:

        Install test dependencies
            pip install pytest pytest-mock

        Run all tests
            pytest tests/


📁 Project Structure

    aimenreco/
    ├── aimenreco/          # Main package
    │   ├── core/           # Scan engine, Wildcard logic & Passive module
    │   │   ├── scanner.py
    │   │   ├── wildcard.py
    │   │   ├── intel.py
    │   │   ├── whois_module.py
    │   │   └── passive.py  # OSINT engine
    │   ├── ui/             # Interface, colors, and banners
    │   │   ├── banners.py
    │   │   ├── colors.py
    │   │   └── logger.py
    │   ├── utils/          # Helpers and resource loaders
    │   │   ├── exceptions.py
    │   │   ├── reporter.py
    │   │   └── helpers.py
    │   ├── resources/      # Lists and extension and json for user_agents and http codes
    │   │   ├── combined_directories.txt
    │   │   ├── common.txt
    │   │   ├── extensions.txt
    │   │   ├── http_codes.json
    │   │   ├── favicons.json
    │   │   └── user_agents.json
    │   └── cli.py          # Entry point
    ├── tests/              # Test folder
    │    │── test_dna.py
    │    │── test_passive.py
    │    │── test_whois.py
    │    │── test_scanner.py
    │    │── test_reporter.py
    │    └── test_helpers.py
    ├── setup.py            # Installation script
    ├── requirements.txt    # Python dependencies
    ├── README.md           # Documentation
    └── CHANGELOG.md        # Tracked changes

🗺️ Roadmap (Future Development)

    v3.2 | Efficiency & Stealth (Current Milestone - COMPLETED ✅)
        - [x] Memory Optimization: Generator-based (`yield`) loading for 1M+ line dictionaries.
        - [x] Advanced Protocol Masking: Intelligent noise reduction for 2xx/3xx schema upgrades (WWW/HTTPS normalization).
        - [x] Quiet Mode (`-q`): Minimalist output for `grep/awk` integration.
        - [x] Unfreezable UI: Forced stdout flushing for real-time progress feedback.
        - [x] Smart Retries: Configurable logic for unstable networks.
        - [x] User-Agent rotation.
        - [x] Graceful Abort: Clean terminal state and thread-safe shutdown on KeyboardInterrupt.
        - [x] Passive recon tree visualization.
        - [x] Passive Resilience: Exponential backoff for 5xx errors in crt.sh.

    v3.3 | Deep Recon Integration (Current Milestone - IN PROGRESS 🚧)
        - [ ] WayBack Machine Integration: Extracting historical subdomains and paths.
        - [ ] Nmap (NSE) Integration: Automatic port scanning upon asset discovery.
        - [X] Tech Profiler: Web technology identification (CMS, Frameworks, WAF).
        - [X] Multi-Source OSINT: Integration with AlienVault, HackerTarget, and WayBack Machine via `providers.json`.
        - [x] Automated Fallback: Logic to switch OSINT providers if one is down.
        - [x] WHOIS Intelligence: Deep domain metadata extraction (Registrar, Dates, Emails).
        - [x] Infrastructure Fingerprinting: Automatic detection of Cloudflare, AWS, and Google Cloud via NS analysis.
        - [x] Global Interrupt Handler: Refactored `UserAbortException` for immediate and clean shutdown across all modules (WHOIS, Passive, and Active).
        - [x] Unit Testing: Expanded Pytest suite to 24+ cases covering WHOIS logic and edge cases.
        - [x] Implementation of a Pytest suite to validate the DNA filtering engine and URL normalization logic.

    v3.4 | Advanced Reporting
        - [ ] Export Formats: Support for PDF and interactive HTML reports.
        - [ ] SQLite Persistence: Local database to track and "diff" recon campaigns.

📈 Comparison: Why Aimenreco?
| Feature                       | Traditional Fuzzers     | Aimenreco |
| Passive Discovery (OSINT)     | ❌                      | ✅ |
| Smart Wildcard Filtering      | ⚠️ (Basic)              | ✅ (DNA Based) |
| Low False Positives           | ❌                      | ✅ |
| 2-in-1 (Subdomains + Dirs)    | ❌                      | ✅ |
| SSL Certificate Parsing       | ❌                      | ✅ |
|Custom 404 DNA Filtering	    |❌ (Shows all info)	     |✅ (Filters size and DNA)

⚖️ Disclaimer
    The use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
```
