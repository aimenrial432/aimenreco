# 🛡️ Aimenreco v3.2 (Performance & Modular Engine dev phase)

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/category-Pentesting-red)
![Status](https://img.shields.io/badge/status-Development--Branch-orange)

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
🔍 Passive Recon (New): Automated subdomain discovery via SSL/TLS certificate transparency logs (crt.sh) with real-time tree-view visualization.

🧬 Wildcard DNA DNA Filtering: Intelligent detection of DNS/HTTP wildcards. It analyzes "server fingerprints" to eliminate false positives, even with dynamic 301/302 redirects.

⚡ Memory-Safe Engine: Optimized using asyncio.BoundedSemaphore and Python generators to process massive wordlists (1M+ lines) with minimal RAM footprint.

🎨 Professional UI: Clean interface with dynamic progress bars and real-time findings.

🕵️ Stealth Rotation: Built-in User-Agent rotation from shared JSON resources to bypass basic WAF fingerprinting.

📦 Modular & Portable: Standard package structure for clean, global installation on Linux systems.

🔍 How It Works (The Intelligence Layer)
Aimenreco is not a "blind" brute-force fuzzer. It employs a strategic three-layer reconnaissance approach to maximize discovery while minimizing noise:
    -Layer 1: OSINT & Certificate Transparency
        The passive module queries CT logs to discover subdomains that might not be listed in public DNS but have issued SSL certificates.

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
        -d, --domain: Target domain (e.g., target.com).
        -w, --wordlist: Path to wordlist.
        -p, --passive: (New) Enable passive subdomain discovery.
        -m, --mode: Scan mode (std or aggressive).
        -x, --extensions: Comma-separated list of extensions (e.g., php,txt,html).
        -o, --output: Save results to a file.
        -q, --quiet: Scan without showing all data on console. Only results will appear
        -v, --verbose: Scan with all data on the console


💡 Usage Examples

    Basic scan:
        sudo aimenreco -d target.com -w common.txt

    Full Recon (Passive + Active):
        sudo aimenreco -d target.com -w common.txt -p

    Full Recon (Passive + Active + Quiet or verbose):
        sudo aimenreco -d target.com -w common.txt -p -q/v

    Aggressive Scan with Extensions:
        sudo aimenreco -d target.com -w common.txt -m aggressive -x php,conf,bak


📁 Project Structure

    aimenreco/
    ├── aimenreco/          # Main package
    │   ├── core/           # Scan engine, Wildcard logic & Passive module
    │   │   ├── scanner.py
    │   │   ├── wildcard.py
    │   │   ├── logger.py
    │   │   └── passive.py  # OSINT engine
    │   ├── ui/             # Interface, colors, and banners
    │   │   ├── banners.py
    │   │   ├── colors.py
    │   │   └── logger.py
    │   ├── utils/          # Helpers and resource loaders
    │   │   └── helpers.py
    │   ├── resources/      # Lists and extension and json for user_agents and http codes
    │   │   ├── combined_directories.txt
    │   │   ├── common.txt
    │   │   ├── extensions.txt
    │   │   ├── http_codes.json
    │   │   └── user_agents.json
    │   └── cli.py          # Entry point
    ├── setup.py            # Installation script
    ├── requirements.txt    # Python dependencies
    ├── README.md           # Documentation
    └── CHANGELOG.md        # Tracked changes

🗺️ Roadmap (Future Development)

    v3.1 | Efficiency & Stealth (Current Goal)
        - [x] Memory Optimization: Generator-based (`yield`) loading for 1M+ line dictionaries.
        - [x] Quiet Mode (`-q`): Minimalist output for `grep/awk` integration.
        - [ ] Smart Retries: Configurable logic for unstable networks.
        - [x] User-Agent rotation.
        - [x] Passive recon tree visualization.

    v3.2 | Deep Recon Integration
        - [ ] Nmap (NSE) Integration: Automatic port scanning upon asset discovery.
        - [ ] ech Profiler: Web technology identification (CMS, Frameworks).

    v3.3 | Advanced Reporting
        - [ ] Export Formats: Support for PDF and interactive HTML reports.
        - [ ] SQLite Persistence: Local database to track and "diff" recon campaigns.

📈 Comparison: Why Aimenreco?
| Feature                       | Traditional Fuzzers     | Aimenreco |
| Passive Discovery (OSINT)     | ❌                      | ✅ |
| Smart Wildcard Filtering      | ⚠️ (Basic)              | ✅ (DNA Based) |
| Low False Positives           | ❌                      | ✅ |
| 2-in-1 (Subdomains + Dirs)    | ❌                      | ✅ |
| SSL Certificate Parsing       | ❌                      | ✅ |

⚖️ Disclaimer
    The use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
```
