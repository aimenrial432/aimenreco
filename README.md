# 🛡️ Aimenreco v3.0 (Modular Framework en desarrollo)

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
🔍 Passive Recon (New): Automated subdomain discovery via SSL/TLS certificate transparency logs (crt.sh).

🧬 Wildcard DNA DNA Filtering: Intelligent detection of DNS/HTTP wildcards. It analyzes "server fingerprints" to eliminate false positives, even with dynamic 301/302 redirects.

⚡ High-Speed Multi-threading: Optimized engine with queue management to handle hundreds of requests per second.

🎨 Professional UI: Clean interface with dynamic progress bars and real-time findings.

📦 Modular & Portable: Standard package structure for clean, global installation on Linux systems.

## 🔍 How It Works (The Intelligence Layer)

Aimenreco is not a "blind" brute-force fuzzer. It employs a strategic three-layer reconnaissance approach:

* **Layer 1: OSINT & Certificate Transparency**
    Before sending a single packet, the passive module queries CT logs to discover subdomains not listed in public DNS.
* **Layer 2: Network DNA Fingerprinting**
    Performs a 10-point stress test to create a profile based on **HTTP Status**, **MD5 Hashing**, and **Size Variance**.
* **Layer 3: Smart Enumeration**
    Filters noise in real-time using the DNA profile, ensuring zero false positives on catch-all servers.

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


💡 Usage Examples

    Basic scan:
        sudo aimenreco -d target.com -w common.txt

    Full Recon (Passive + Active):
        sudo aimenreco -d target.com -w common.txt -p

    Aggressive Scan with Extensions:
        sudo aimenreco -d target.com -w common.txt -m aggressive -x php,conf,bak


📁 Project Structure

    aimenreco/
    ├── aimenreco/          # Main package
    │   ├── core/           # Scan engine, Wildcard logic & Passive module
    │   │   ├── scanner.py
    │   │   ├── wildcard.py
    │   │   └── passive.py  # OSINT engine
    │   ├── ui/             # Interface, colors, and banners
    │   ├── utils/          # Helpers and resource loaders
    │   └── cli.py          # Entry point
    ├── setup.py            # Installation script
    ├── requirements.txt    # Python dependencies
    ├── README.md           # Documentation
    └── CHANGELOG.md        # Tracked changes

🗺️ Roadmap (Future Development)
Aimenreco's goal is to provide a unified framework covering 100% of Phase 1 (Passive Recon) and Phase 2 (Active Recon) of a professional Pentest.

v3.1 | Efficiency & Stealth (Current Goal)
    [ ] Memory Optimization: Implement generator-based (yield) wordlist loading to handle massive dictionaries (1M+ lines) with minimal RAM usage.
    [ ] Quiet Mode (-q): Minimalist output for seamless integration with other CLI tools (grep, awk, notify).
    [ ] Smart Retries: Configurable retry logic to handle unstable network environments or Rate Limiting.

v3.2 | Deep Recon Integration
    [ ] Nmap Scripting Engine (NSE): Automatic port scanning and service detection upon finding a live asset.
    [ ] Tech Profiler: Identification of web technologies (CMS, Server headers, Frameworks) using fingerprinting.

v3.3 | Advanced Reporting
    [ ] Export Formats: Native support for professional PDF and interactive HTML reports.
    [ ] SQLite Persistence: Local database storage to track recon campaigns and perform "diffs" between scans.

### 📈 Comparison: Why Aimenreco?
| Feature | Traditional Fuzzers | Aimenreco |
| :--- | :---: | :---: |
| **Passive Discovery (OSINT)** | ❌ | ✅ |
| **Smart Wildcard Filtering** | ⚠️ (Basic) | ✅ (DNA Based) |
| **Low False Positives** | ❌ | ✅ |
| **2-in-1 (Subdomains + Dirs)** | ❌ | ✅ |
| **SSL Certificate Parsing** | ❌ | ✅ |

⚖️ Disclaimer
    The use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
```
