import pytest
from typing import Any, List, Set, Generator
from aimenreco.core.scanner import Scanner
from aimenreco.utils.reporter import Reporter
from aimenreco.core.passive import PassiveScanner

# =================================================================
# SECTION 1: SCANNER CORE LOGIC TESTS
# =================================================================

def test_scanner_noise_filtering_logic(logger: Any) -> None:
    """
    Test Case: Advanced Noise & Triple-DNA Filtering.
    
    Verifies that the engine correctly identifies 'noise' based on:
    - DNA MD5 Signature matches.
    - DNA Status + Size tolerance (±15 bytes) + Words + Title.
    - Protocol upgrades (HSTS/SSL redirects).
    - Multi-Size manual filters.
    """
    # Mock Wildcard DNA: (has_w, hash, size, status, redir, words, title)
    w_data = (True, "d41d8cd98f00b204e9800998ecf8427e", 800, 404, None, 50, "Not Found")
    
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=w_data,
        logger=logger,
        sf="5555,808,0"  # Multi-size filter string
    )

    # CASE 1: Exact DNA Hash Match
    noise, _ = scanner.is_noise(200, 100, "d41d8cd98f00b204e9800998ecf8427e", "", "http://target.com/test", 10, "Title")
    assert noise is True

    # CASE 2: Triple-DNA Match (Status 404 + Size 810 [within ±15] + Words 50 + Title "Not Found")
    noise, n_type = scanner.is_noise(404, 810, "diff_hash", "", "http://target.com/test", 50, "Not Found")
    assert noise is True
    assert n_type == "dna"

    # CASE 3: Protocol Masking (HTTP -> HTTPS redirect of the same path)
    noise, n_type = scanner.is_noise(301, 0, "hash", "https://target.com/test", "http://target.com/test", 0, "")
    assert noise is True
    assert n_type == "protocol"

    # CASE 4: Multi-Size Manual Filter
    noise, n_type = scanner.is_noise(200, 5555, "hash", "", "http://target.com/test", 100, "OK")
    assert noise is True
    assert n_type == "manual"

    # CASE 5: Real Finding (Does not match DNA or manual filters)
    noise, _ = scanner.is_noise(200, 9999, "unique_hash", "", "http://target.com/secret", 500, "Admin Panel")
    assert noise is False

def test_scanner_sf_initialization(logger: Any) -> None:
    """
    Test Case: Manual Size Filter Initialization.
    
    Verifies that the Scanner correctly parses various input formats for the -sf flag
    into a set of integers.
    """
    dna = (False, "", 0, 0, None, 0, "")
    
    # Case A: String with multiple values
    s1 = Scanner("http://t.com", 1, 1, dna, logger, sf="100, 200,300")
    assert s1.sf == {100, 200, 300}

    # Case B: Single integer
    s2 = Scanner("http://t.com", 1, 1, dna, logger, sf=808)
    assert s2.sf == {808}

    # Case C: None
    s3 = Scanner("http://t.com", 1, 1, dna, logger, sf=None)
    assert s3.sf == set()

def test_scanner_extension_logic(logger: Any) -> None:
    """
    Test Case: Multi-extension path generation.
    
    Ensures that prepare_wordlist yields the base word plus all 
    specified extensions.
    """
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=(False, None, 0, 0, None, 0, ""),
        logger=logger,
        extensions_arg=["php", "txt"]
    )
    
    # Define the base words
    word_list: List[str] = ["config"]
    
    # FIX: Convert List to Generator to satisfy the type checker
    word_gen: Generator[str, None, None] = (word for word in word_list)
    
    # Execute the method
    paths: List[str] = list(scanner.prepare_wordlist(word_gen))
            
    assert "config" in paths
    assert "config.php" in paths
    assert "config.txt" in paths
    assert len(paths) == 3

# =================================================================
# SECTION 2: CLI ORCHESTRATION & PERSISTENCE TESTS
# =================================================================

def test_cli_persistence_without_passive_flag(tmp_path: Any, logger: Any) -> None:
    """
    Test Case: Independent Active Phase Reporting.
    
    Ensures that active findings are saved using the generic 'write_section' 
    method even if the passive phase is skipped.
    """
    report_file = tmp_path / "active_only.txt"
    reporter = Reporter(str(report_file), logger=logger)
    
    findings: List[str] = ["http://target.com/admin", "http://target.com/.env"]
    reporter.write_section("Active Scan (target.com)", findings)
    
    content: str = report_file.read_text()
    assert "ACTIVE SCAN (TARGET.COM)" in content
    assert "/.env" in content
    assert "Total items in section: 2" in content

def test_cli_passive_intel_handling(tmp_path: Any, logger: Any) -> None:
    """
    Test Case: Intelligence Metadata Storage and Formatting.

    Validates that WHOIS metadata from PassiveScanner is correctly passed to the
    Reporter and written with consistent labels.
    """
    report_file = tmp_path / "intel_report.txt"
    reporter = Reporter(str(report_file), logger=logger)
    p_scanner = PassiveScanner("example.com", logger=logger)
    
    p_scanner.whois_data = {
        'registrar': 'MarkMonitor',
        'creation_date': '1997-09-15',
        'org': 'Google LLC',
        'name_servers': ['ns1.google.com']
    }
    
    if p_scanner.whois_data:
        reporter.write_intelligence("example.com", p_scanner.whois_data)
        
    content: str = report_file.read_text()
    
    assert "[+] DOMAIN INTELLIGENCE: example.com" in content
    assert "Registrar:" in content 
    assert "MarkMonitor" in content
    assert "Organization:" in content
    assert "Google LLC" in content

def test_cli_graceful_abort_reporting(tmp_path: Any, logger: Any) -> None:
    """
    Test Case: Data Persistence on User Interruption.
    
    Verifies that the reporter persists partial results when a scan 
    is interrupted (e.g., Ctrl+C).
    """
    report_file = tmp_path / "aborted_scan.txt"
    reporter = Reporter(str(report_file), logger=logger)
    
    partial_results: List[str] = ["http://target.com/index.php"]
    reporter.write_section("Partial Active Results (Aborted)", partial_results)
    
    content: str = report_file.read_text()
    assert "PARTIAL ACTIVE RESULTS (ABORTED)" in content
    assert "index.php" in content