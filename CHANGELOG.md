# Changelog

All notable changes to AimenReco will be documented in this file.

## [3.1.0] - 2026-03-14

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
