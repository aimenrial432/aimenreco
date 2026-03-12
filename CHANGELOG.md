# Changelog

All notable changes to AimenReco will be documented in this file.

## [3.0.0] - 2026-03-12

### Changed

- **BREAKING**: Renamed project from DirForcer to AimenReco
  - Updated all references in code
  - New branding and project identity
- Initialized Git repository with proper documentation
- Created comprehensive README and CHANGELOG

### Note

This version marks the official rename and proper documentation of the project.
Previous development (v0.1 - v2.5) was not version-controlled.

Historical context: - v0.1: Forked from original DirForce repo (~40 lines) - v1.0: Expanded to 230+ lines with threading and basic wildcard detection - v2.0: Modular architecture implemented - v2.5: Stealth mode, multiple output formats, advanced wildcard detection - v3.0: Renamed to AimenReco, proper documentation and version control

## [2.5.0] - 2026-03-11 (Retroactive)

**Note**: This version was developed before Git initialization.
Dates and changes are documented retroactively based on development notes.

### Added

- Stealth mode as default
  - Low threads (40), high delay (100ms)
  - Randomized User-Agent
- Aggressive mode (opt-in via `-m`)
- Wildcard detection for 301/302 redirects
- Multiple output formats (txt, json)

### Changed

- Renamed `main.py` to `cli.py`
- Improved CLI argument structure

## [2.0.0] - 2026-03-09 (Retroactive)

### Added

- Detailed help menu
- Configurable threading and delays
- Modular architecture
- Threading control

### Changed

- Refactored from monolithic to modular design

## [1.0.0] - 2026-03-07 (Retroactive)

### Added

- Expanded from 50 to 300+ lines
- Basic wildcard detection
- Threading support
- File output functionality
- Progress indicators

### Changed

- Complete rewrite of core logic

## [0.1.0] - 2026-03-05 (Retroactive)

### Initial

- Forked from DirForce repository (~40 lines)
- Basic directory fuzzing

**Retroactive Note**:
Versions 0.1 through 2.5 were developed without Git version control.
This changelog has been reconstructed from development notes and code analysis.
Proper version control and documentation begins with v3.0.0.

---

**Future Development**:
Starting from v3.0.0, all changes will be properly tracked in Git with:

- Atomic commits for each feature
- Proper commit messages
- Version tags
- Detailed changelog updates
