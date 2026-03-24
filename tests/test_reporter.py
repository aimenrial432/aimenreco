import os
import pytest
from aimenreco.utils.reporter import Reporter

def test_reporter_initialization(tmp_path):
    """
    Test Case: Report File Header Creation.
    Ensures that simply initializing a Reporter with a path 
    creates the file and writes the framework header.
    """
    report_file = tmp_path / "header_test.txt"
    rep = Reporter(str(report_file))
    
    assert report_file.exists()
    content = report_file.read_text()
    assert "AIMENRECO DISCOVERY REPORT" in content

def test_reporter_intelligence_section(tmp_path):
    """
    Test Case: WHOIS Data Formatting.
    Verifies that technical metadata is correctly structured 
    in the output file.
    """
    report_file = tmp_path / "intel.txt"
    rep = Reporter(str(report_file))
    
    intel_data = {
        'registrar': 'NameCheap',
        'org': 'CyberCorp',
        'name_servers': ['ns1.dns.com', 'ns2.dns.com']
    }
    
    rep.write_intelligence("target.com", intel_data)
    content = report_file.read_text()
    
    assert "[+] DOMAIN INTELLIGENCE: target.com" in content
    assert "Registrar:    NameCheap" in content
    assert "Organization: CyberCorp" in content
    assert "ns1.dns.com" in content

def test_reporter_no_path_graceful(tmp_path):
    """
    Test Case: Silent Mode (No -o flag).
    Confirms that the Reporter does not crash when output_path is None.
    """
    rep = Reporter(None)
    try:
        rep.write_section("Test", ["data"])
        rep.write_intelligence("test.com", {"data": "val"})
    except Exception as e:
        pytest.fail(f"Reporter crashed without output path: {e}")