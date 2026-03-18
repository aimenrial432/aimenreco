# Changelog

All notable changes to AimenReco will be documented in this file.

## [3.2.1] - 2026-03-18 (Dev Phase)

### Added

- **WhoisAnalyzer Module**: New engine to gather domain intelligence during the passive phase.
- **Cloud Infrastructure Detection**: Automatic identification of WAFs/Providers based on Nameservers.
- **Custom Exception Handling**: Implemented `UserAbortException` to standardize `Ctrl+C` behavior across the entire framework.

### Changed

- **Passive Phase Flow**: The passive scan now starts with a WHOIS lookup before querying CT logs.
- **Retry Logic**: Improved WHOIS resilience with exponential backoff and jitter.

### Fixed

- **Zombie Retries**: Fixed a bug where `KeyboardInterrupt` was being caught by generic exception blocks, preventing the scan from stopping immediately.
- **Terminal Cleanup**: Ensured `^C` characters don't mess up the terminal UI on exit.

### Security & Quality

- Added `test_whois.py` with 100% coverage on parsing and error handling.

---

## [3.2.0] - 2026-03-17

### Added

- **Full Test Coverage (20/20)**: Reached 100% success rate across the entire suite (`pytest`).
  - **DNA Stress Tests**: Validated statistical profiling on 2xx/3xx/4xx responses.
  - **Passive Discovery**: Tested crt.sh parsing and exponential backoff.
  - **Scanner Core**: Verified multi-threading safety and result filtering logic.
  - **Utility Logic**: Path-independent resource loading and URL normalization.
- **Improve Layer**: Implemented immediate path validation for wordlist streaming, preventing generator initialization on non-existent files.
- **Enhanced OSINT Filtering**: Added strict FQDN validation to the passive module to prevent out-of-scope leaks (e.g., filtering `target.com.attacker.com`).

### Fixed

- **The "Port Bug"**: Resolved an issue where the DNA engine and Passive Scanner would fail if the target input included a port (e.g., `example.com:8443`). The engine now strips ports and paths to focus on the root domain.
- **Generator Validation**: Fixed a bug where `stream_wordlist` returned a generator object even if the file didn't exist, causing delayed crashes. It now returns `None` immediately.
- **WWW/Protocol Redundancy**: Improved `clean_url` and `PassiveScanner` to handle cases where `www.` or protocols were nested or malformed.

### Changed

- **Modular Engine Refactoring**: Cut the scanning logic from the UI/CLI to allow better testability and future API integration.

---

## [3.2.0] - 2026-03-16

### Added

- **Pytest Suite Integration**: Implemented a comprehensive testing framework covering DNA Stress Tests, Passive Recon resilience, and Scanner threading logic.
- **Exception Architecture**: Centralized error handling in `aimenreco.utils.exceptions` to decouple core logic from the CLI, following clean code principles.

### Fixed

- **Graceful Termination (DNA Phase)**: Fixed a bug where Ctrl+C during the DNA Stress Test would trigger a "Critical Error" instead of aborting. The process now propagates `UserAbortException` correctly.
- **Terminal Buffer Management**: Improved `sys.stdout` flushing to ensure the terminal is cleared of `^C` artifacts, maintaining a professional CLI aesthetic.
- **Time Calculation Safety**: Fixed `UnboundLocalError` in the final report when a scan was aborted before the active phase timer initialized.

### Changed

- **Modular Exception Handling**: Updated `WildcardAnalyzer` to avoid catching `UserAbortException` in generic blocks, allowing instant UI feedback upon user interruption.

---

## [3.2.0] - 2026-03-15

### Added

- **Unfreezable UI (The Heartbeat Update**): Implemented forced flushing in Logger.status to ensure a smooth, constant progress bar, eliminating visual lag during high-speed scans.
- **Resilient Passive Engine**: Added automatic retry support for server-side errors (500-599 range) using Exponential Backoff (incremental waits of 10s, 20s, and 40s).
- **Universal Protocol Masking**: New intelligent filter that normalizes 2xx and 3xx responses. It prevents duplicates by detecting when a server responds with success or redirection based only on cosmetic schema changes (HTTP/HTTPS) or subdomains (e.g., WWW).
- **Graceful Termination**: Redesigned SIGINT (Ctrl+C) capture system to perform a clean thread shutdown, clear the terminal buffer, and provide an instant final report without visual artifacts.
- **Manual Size Filter (-sf)**: Added the ability for users to manually exclude specific response sizes from the results, providing extra control over edge-case noise.

### Changed

- **Enhanced Wildcard DNA**: The pre-scan engine is now more aggressive, detecting "catch-all" behaviors across the 400-600 error range (including 501/502 errors from load balancers).
- **Code Quality**: Full internal source documentation using Docstrings following the PEP 257 standard for all core methods.

### Fixed

- **Terminal Overflow**: Corrected the visual bug where the ^C prompt displaced the progress bar, breaking the CLI aesthetic.
- **Zombie Threads**: The ThreadPoolExecutor now cancels pending futures immediately upon aborting, releasing system resources instantly.

---

## [3.2] - 2026-03-14

### Added

- **Passive Recon Engine**: New OSINT module using Certificate Transparency (CT) logs via crt.sh.
- **DNA Stress Tests**: Preliminary network analysis to detect wildcard DNS and stable vs. unstable servers.
- **Advanced Filtering**: Stage 3.2 cleaning pipeline to normalize subdomains (removes ports, paths, and malformed strings).
- **Quiet Mode (-q)**: Streamlined output for automation, removing banners and progress noise.

### Fixed

- **Logger Integration**: Fixed `TypeError` in `PassiveScanner` by correctly passing the logger instance through the CLI.
- **Resource Loading**: Improved memory-efficient wordlist streaming for large-scale discovery.
- **Wildcard False Positives**: Better detection of "Stable Servers" to prevent junk results in active scans.

### Changed

- **Documentation**: All internal source code comments migrated to English for better maintainability.
- **UI/UX**: Improved visual tree display for passive results using `└─` formatting.

---

## [3.1.0] - 2026-03-13

### Added

- **High-Performance Memory Engine**: Replaced full wordlist loading with a generator-based (yield) stream. This allows processing massive dictionaries (millions of lines) with near-zero RAM impact.
- **Enhanced OSINT Visualization**: Integrated a real-time "tree-style" output (└─) for passive subdomain discovery, providing instant feedback before the active scan starts.
- **Smart Resource Loader**: Implemented get_resource_path to handle internal package files (wordlists, JSONs) consistently across any installation path.
- **Advanced Help Manual**: Redesigned the -h/--help interface with a professional security-tool aesthetic, using high-contrast ANSI colors and precision-aligned columns.

### Changed

- **Concurrency Management**: Migrated to asyncio.BoundedSemaphore within the scanner core to prevent OS socket exhaustion and improve thread stability.
- **Passive Module Sanitization**: Refined URL cleaning logic to strip protocols (http/https) and trailing paths from crt.sh raw data, ensuring only clean FQDNs are processed.
- **Stealth Optimization**: Centralized User-Agent rotation using a dedicated user_agents.json resource file for easier updates and better fingerprinting protection.
- **UI Refresh**: Updated the main banner and status messages for a more polished "Framework" feel.

### Fixed

- Fixed a bug where certain crt.sh entries with multiple SANs (Subject Alternative Names) would cause duplicate or malformed subdomain output.
- Resolved an issue with the CLI padding that caused misalignment in the help menu on certain terminal widths.

---

## [3.0.0] - 2026-03-12

### Added

- **Passive Recon Module**: Integrated a new `passive.py` engine for subdomain discovery using Certificate Transparency (CT) logs via `crt.sh`.
- **Subdomain Persistence**: Automated saving of passive discovery results to `subdomains_<domain>.txt`.
- **Wildcard DNA Filtering**: Implemented a sophisticated filtering system that analyzes HTTP status codes, MD5 content hashes, and response size variance to eliminate dynamic false positives.
- **Auto-Retry Logic**: Added resilience to the passive module to handle network timeouts and API rate-limiting gracefully.

### Changed

- **BREAKING**: Officially renamed the project from **DirForcer** to **AimenReco** to reflect its evolution into a full reconnaissance framework.
- **Improved Scanner Core**: Optimized the threading engine to synchronize with pre-scan Wildcard analysis, significantly reducing processing overhead.
- **Enhanced CLI**:
  - Added support for the `-p` (passive) flag.
  - Refactored argument parsing to allow `--help` access without requiring root privileges.
- **Project Standardization**: Initialized Git repository with professional documentation, including a comprehensive README and this CHANGELOG.

---

## [2.5.0] - 2026-03-11 (Retroactive)

> **Note**: This version was developed prior to Git initialization. Changes are documented retroactively.

### Added

- **Stealth Mode (Default)**:
  - Optimized for low-noise environments with controlled thread counts.
  - Implemented randomized **User-Agent** headers to bypass basic WAF/IDS signatures.
- **Aggressive Mode**: Opt-in high-performance mode via `-m aggressive` for authorized laboratory environments.
- **Smart Wildcard Detection**: Initial logic to handle 301/302 redirects during directory fuzzing.
- **Multi-Format Output**: Added support for both plain text (`.txt`) and machine-parseable (`.json`) results.

### Changed

- **Refactoring**: Renamed `main.py` to `cli.py` to align with Python package conventions.
- **CLI UX**: Improved argument structure for better usability.

---

## [2.0.0] - 2026-03-09 (Retroactive)

### Added

- **Modular Architecture**: Transitioned from a single-file script to a structured package (`core/`, `ui/`, `utils/`).
- **Granular Control**: User-defined threading and timeout configurations.

### Changed

- **Codebase Overhaul**: Complete refactoring to improve maintainability and future scalability.

---

## [1.0.0] - 2026-03-07 (Retroactive)

### Added

- **Performance**: Introduced multi-threading support for concurrent requests.
- **Core Logic**: Basic wildcard detection and initial progress indicators.
- **Output Engine**: Added functionality to save findings to local files.

---

## [0.1.0] - 2026-03-05 (Retroactive)

### Initial

- **Project Inception**: Forked from original `DirForce` repository.
- **Core Feature**: Basic directory fuzzing implementation.

---

**Retroactive Note**:
Versions 0.1 through 2.5 were developed without Git version control.
This changelog has been reconstructed from development notes and code analysis.
Proper version control and documentation begins with v3.0.0.

---

### 🛡️ Versioning Policy

Starting from **v3.0.0**, all changes are tracked via Git following these principles:

- **Atomic Commits**: One feature/fix per commit.
- **Semantic Versioning**: Major (breaking), Minor (feature), Patch (fix).
- **Documentation First**: Every feature must be reflected in the README and Changelog.
