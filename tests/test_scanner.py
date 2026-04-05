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
    Test Case: Advanced Noise & Triple-DNA Filtering.
    Verifies that the engine correctly identifies 'noise' based on:
    - DNA MD5 Signature matches.
    - DNA Status + Size tolerance (±15 bytes) + Words + Title.
    - Protocol upgrades (HSTS/SSL redirects).
    - Multi-Size manual filters (-sf 808,0,1500).
    """
    # Mock Wildcard DNA: (has_w, hash, size, status, redir, words, title)
    w_data = (True, "d41d8cd98f00b204e9800998ecf8427e", 800, 404, None, 50, "Not Found")
    
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=w_data,
        logger=FakeLogger(),
        sf="5555,808,0" # Testing multi-size filter as a string (CLI style)
    )

    # CASE 1: Exact DNA Hash Match (Direct hit on known error page)
    noise, _ = scanner.is_noise(200, 100, "d41d8cd98f00b204e9800998ecf8427e", "", "http://target.com/test", 10, "Title")
    assert noise is True

    # CASE 2: Triple-DNA Match (Status 404 + Size 810 [within ±15] + Words 50 + Title "Not Found")
    noise, n_type = scanner.is_noise(404, 810, "diff_hash", "", "http://target.com/test", 50, "Not Found")
    assert noise is True
    assert n_type == "dna"

    # CASE 3: Protocol Masking (Redirecting http -> https of the same URL)
    noise, n_type = scanner.is_noise(301, 0, "hash", "https://target.com/test", "http://target.com/test", 0, "")
    assert noise is True
    assert n_type == "protocol"

    # CASE 4: Multi-Size Manual Filter (First value: 5555)
    noise, n_type = scanner.is_noise(200, 5555, "hash", "", "http://target.com/test", 100, "OK")
    assert noise is True
    assert n_type == "manual"

    # CASE 5: Multi-Size Manual Filter (Second value: 808)
    noise, n_type = scanner.is_noise(200, 808, "hash", "", "http://target.com/test", 100, "OK")
    assert noise is True
    assert n_type == "manual"

    # CASE 6: Real Finding (Does not match DNA nor manual filters)
    noise, _ = scanner.is_noise(200, 9999, "unique_hash", "", "http://target.com/secret", 500, "Admin Panel")
    assert noise is False

def test_scanner_sf_initialization():
    """
    Test Case: Manual Size Filter Initialization.
    Verifies that the Scanner correctly parses various input formats for the -sf flag.
    """
    # Case A: String with multiple values
    s1 = Scanner("http://t.com", 1, 1, (False, "", 0, 0, ""), FakeLogger(), sf="100, 200,300")
    assert s1.sf == {100, 200, 300}

    # Case B: Single integer
    s2 = Scanner("http://t.com", 1, 1, (False, "", 0, 0, ""), FakeLogger(), sf=808)
    assert s2.sf == {808}

    # Case C: None / Empty
    s3 = Scanner("http://t.com", 1, 1, (False, "", 0, 0, ""), FakeLogger(), sf=None)
    assert s3.sf == set()

def test_scanner_extension_logic():
    """
    Test Case: Multi-extension path generation via prepare_wordlist.
    Ensures that the generator yields the base word plus all extended versions.
    """
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=(False, None, 0, 0, None),
        logger=FakeLogger(),
        extensions_arg=["php", "txt"]
    )
    
    word_gen = ["config"]
    paths = list(scanner.prepare_wordlist(word_gen))
            
    assert "config" in paths
    assert "config.php" in paths
    assert "config.txt" in paths
    assert len(paths) == 3

# =================================================================
# SECTION 2: CLI ORCHESTRATION & PERSISTENCE TESTS
# =================================================================

def test_cli_persistence_without_passive_flag(tmp_path):
    """
    Test Case: Independent Active Phase Reporting.
    Ensures that active findings are saved even if PassiveScanner was never used.
    """
    report_file = tmp_path / "active_only.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    
    findings = ["http://target.com/admin", "http://target.com/.env"]
    reporter.write_section("Active Scan (target.com)", findings)
    
    content = report_file.read_text()
    assert "==== ACTIVE SCAN (TARGET.COM) ====" in content
    assert "/.env" in content
    assert "Total items in section: 2" in content

def test_cli_passive_intel_handling(tmp_path):
    """
    Test Case: Intelligence Metadata Storage and Formatting.

    Validates that WHOIS metadata from PassiveScanner is correctly passed to the
    Reporter and written to the output file. It uses flexible string matching to 
    ensure compatibility with various spacing or indentation styles in the 
    final discovery report.
    """
    report_file = tmp_path / "intel_report.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    p_scanner = PassiveScanner("example.com", logger=FakeLogger())
    
    p_scanner.whois_data = {
        'registrar': 'MarkMonitor',
        'creation_date': '1997-09-15',
        'org': 'Google LLC',
        'name_servers': ['ns1.google.com']
    }
    
    if p_scanner.whois_data:
        reporter.write_intelligence("example.com", p_scanner.whois_data)
        
    content = report_file.read_text()
    
    assert "[+] DOMAIN INTELLIGENCE: example.com" in content
    assert "Registrar:" in content 
    assert "MarkMonitor" in content
    assert "Organization:" in content
    assert "Google LLC" in content

def test_cli_graceful_abort_reporting(tmp_path):
    """
    Test Case: Data Persistence on User Interruption (Ctrl+C).
    Verifies that the reporter can save partial results caught during a UserAbortException.
    """
    report_file = tmp_path / "aborted_scan.txt"
    reporter = Reporter(str(report_file), logger=FakeLogger())
    
    partial_results = ["http://target.com/index.php"]
    reporter.write_section("Partial Active Results (Aborted)", partial_results)
    
    content = report_file.read_text()
    assert "PARTIAL ACTIVE RESULTS (ABORTED)" in content
    assert "index.php" in content