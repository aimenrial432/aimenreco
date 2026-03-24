import pytest
import os
from aimenreco.core.scanner import Scanner
from aimenreco.utils.reporter import Reporter
from aimenreco.core.passive import PassiveScanner

class FakeLogger:
    """Mock logger for core engine and CLI workflow testing."""
    quiet = True
    verbose = 0
    def info(self, m): pass
    def status(self, m): pass
    def debug(self, m): pass
    def error(self, m): pass
    def warn(self, m): pass
    def tree(self, label, value, color=None, is_last=False): pass

# =================================================================
# SECTION 1: SCANNER CORE LOGIC TESTS
# =================================================================

def test_scanner_noise_filtering_logic():
    """
    Test Case: Advanced Noise & DNA Filtering.
    Verifies that the engine correctly identifies 'noise' based on:
    - DNA MD5 Signature matches.
    - DNA Status + Size tolerance (±15 bytes).
    - Protocol upgrades (HSTS/SSL redirects).
    - Manual size filters (-sf).
    """
    # Mock Wildcard DNA (has_wildcard, md5_hash, avg_size, base_status, redir_loc)
    w_data = (True, "d41d8cd98f00b204e9800998ecf8427e", 800, 404, None)
    
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=w_data,
        logger=FakeLogger(),
        sf=5555 # Manual size filter
    )

    # CASE 1: Exact DNA Hash Match (Direct hit on known error page)
    noise, _ = scanner.is_noise(200, 100, "d41d8cd98f00b204e9800998ecf8427e", "", "http://target.com/test")
    assert noise is True

    # CASE 2: DNA Size Tolerance (Size 810 is within ±15 of baseline 800)
    noise, _ = scanner.is_noise(404, 810, "diff_hash", "", "http://target.com/test")
    assert noise is True

    # CASE 3: Protocol Masking (Redirecting http -> https of the same URL)
    noise, n_type = scanner.is_noise(301, 0, "hash", "https://target.com/test", "http://target.com/test")
    assert noise is True
    assert n_type == "protocol"

    # CASE 4: Manual Size Filter match
    noise, _ = scanner.is_noise(200, 5555, "hash", "", "http://target.com/test")
    assert noise is True

    # CASE 5: Real Finding (Does not match any noise pattern)
    noise, _ = scanner.is_noise(200, 9999, "unique_hash", "", "http://target.com/secret")
    assert noise is False

def test_scanner_extension_logic():
    """
    Test Case: Multi-extension path generation.
    Ensures that if the user provides extensions (e.g., php,txt), 
    the scanner correctly prepares the target word list.
    """
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=(False, None, 0, 0, None),
        logger=FakeLogger(),
        extensions_arg=["php", "txt"]
    )
    
    paths = ["config"]
    if scanner.extensions:
        for ext in scanner.extensions:
            paths.append(f"config.{ext}")
            
    assert "config.php" in paths
    assert "config.txt" in paths
    assert len(paths) == 3

# =================================================================
# SECTION 2: CLI ORCHESTRATION & PERSISTENCE TESTS
# =================================================================

def test_cli_persistence_without_passive_flag(tmp_path):
    """
    Test Case: Independent Active Phase Reporting.
    Simulates the CLI logic where '-p' (passive) is NOT set but '-o' is.
    Ensures that active findings are saved even if PassiveScanner was never used.
    """
    report_file = tmp_path / "active_only.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    
    # Simulate data that would come from scanner.run()
    findings = ["http://target.com/admin", "http://target.com/.env"]
    
    # Mimic the 'finally' block in cli.py
    reporter.write_section("Active Scan (target.com)", findings)
    
    content = report_file.read_text()
    assert "==== ACTIVE SCAN (TARGET.COM) ====" in content
    assert "/.env" in content
    assert "Total items in section: 2" in content

def test_cli_passive_intel_handling(tmp_path):
    """
    Test Case: Intelligence Metadata Storage.
    Ensures that if the passive flag is enabled, WHOIS intelligence 
    is correctly passed to the reporter from the PassiveScanner object.
    """
    report_file = tmp_path / "intel_report.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    p_scanner = PassiveScanner("example.com", logger=FakeLogger())
    
    # Manually inject data that WhoisAnalyzer would return
    p_scanner.whois_data = {
        'registrar': 'MarkMonitor',
        'creation_date': '1997-09-15',
        'org': 'Google LLC',
        'name_servers': ['ns1.google.com']
    }
    
    # Mimic the 'if args.passive' block in cli.py
    if p_scanner.whois_data:
        reporter.write_intelligence("example.com", p_scanner.whois_data)
        
    content = report_file.read_text()
    assert "[+] DOMAIN INTELLIGENCE: example.com" in content
    assert "Registrar:    MarkMonitor" in content
    assert "Organization: Google LLC" in content

def test_cli_graceful_abort_reporting(tmp_path):
    """
    Test Case: Data Persistence on User Interruption (Ctrl+C).
    Verifies that the reporter can save partial results caught 
    from the scanner object during a UserAbortException.
    """
    report_file = tmp_path / "aborted_scan.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    
    # Simulate partial results captured before SIGINT
    partial_results = ["http://target.com/index.php"]
    
    # Mimic the 'except UserAbortException' block in cli.py
    reporter.write_section("Partial Active Results (Aborted)", partial_results)
    
    content = report_file.read_text()
    assert "PARTIAL ACTIVE RESULTS (ABORTED)" in content
    assert "index.php" in content