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
    Verifies that technical metadata is correctly structured in the output file
    without being overly sensitive to exact spacing/indentation.
    """
    from aimenreco.utils.reporter import Reporter # Import inside if needed or at top
    report_file = tmp_path / "intel.txt"
    rep = Reporter(str(report_file))

    intel_data = {
        'registrar': 'NameCheap',
        'org': 'CyberCorp',
        'name_servers': ['ns1.dns.com', 'ns2.dns.com']
    }

    rep.write_intelligence("target.com", intel_data)
    content = report_file.read_text()

    # We check for existence of keys and values independently of exact whitespace
    assert "[+] DOMAIN INTELLIGENCE: target.com" in content
    assert "Registrar:" in content and "NameCheap" in content
    assert "Organization:" in content and "CyberCorp" in content
    assert "ns1.dns.com" in content
    assert "ns2.dns.com" in content