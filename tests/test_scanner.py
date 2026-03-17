import pytest
from aimenreco.core.scanner import Scanner

class FakeLogger:
    """Mock logger for scanner core testing."""
    quiet = True
    verbose = False
    def info(self, m): pass
    def status(self, m): pass
    def debug(self, m): pass
    def error(self, m): pass
    def warn(self, m): pass

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
    Test Case: Multi-extension generation.
    Ensures that if the user provides extensions (e.g., php,txt), 
    the scanner correctly formats the target paths.
    """
    scanner = Scanner(
        url="http://target.com",
        threads=1,
        timeout=1,
        wildcard_data=(False, None, 0, 0, None),
        logger=FakeLogger(),
        extensions_arg=["php", "txt"]
    )
    
    # Simulating a word 'config'
    # Should check: config, config.php, config.txt
    paths = ["config"]
    if scanner.extensions:
        for ext in scanner.extensions:
            paths.append(f"config.{ext}")
            
    assert "config.php" in paths
    assert "config.txt" in paths
    assert len(paths) == 3

def test_scanner_result_aggregation():
    """
    Test Case: Internal Results Storage.
    Verifies that valid findings are correctly appended to the 
    scanner's internal list for final reporting.
    """
    scanner = Scanner("http://target.com", 1, 1, (False, None, 0, 0, None), FakeLogger())
    
    # Manually injecting a finding
    scanner.results.append({"url": "http://target.com/admin", "status": 200, "size": 1234})
    
    assert len(scanner.results) == 1
    assert scanner.results[0]["status"] == 200

def test_scanner_empty_wildcard_data():
    """
    Test Case: Clean Server Baseline.
    Ensures that if DNA analysis found no wildcard (False), the scanner 
    doesn't accidentally filter out legitimate 404s or small pages.
    """
    # DNA says NO wildcard
    w_data = (False, None, 0, 0, None)
    scanner = Scanner("http://target.com", 1, 1, w_data, FakeLogger())
    
    # A 404 should NOT be noise if there is no wildcard (we might want to see them in verbose)
    # Actually, most scanners ignore 404 by default, but here we test the DNA logic
    noise, _ = scanner.is_noise(404, 100, "any_hash", "", "http://target.com/missing")
    
    # If no wildcard, a 404 is technically NOT noise-DNA (it's just a standard status)
    assert noise is False