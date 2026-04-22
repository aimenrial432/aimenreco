import os
from typing import Any, Dict, List
from aimenreco.utils.reporter import Reporter

def test_reporter_initialization(tmp_path: Any) -> None:
    """
    Test Case: Report File Header Creation.
    
    Verifies that initializing the Reporter class automatically creates 
    the target file and writes the framework's mandatory identification header.
    """
    # Create a path for the temporary report
    report_path = tmp_path / "header_test.txt"
    report_str: str = str(report_path)
    
    # Initialize reporter (Passing None as logger for the test)
    rep = Reporter(report_str, logger=None)
    
    # Assertions
    assert report_path.exists(), "The report file should be created upon initialization"
    
    content: str = report_path.read_text()
    assert "AIMENRECO DISCOVERY REPORT" in content
    assert "=" * 10 in content  # Checks for visual separators

def test_reporter_intelligence_section(tmp_path: Any) -> None:
    """
    Test Case: Intelligence Data Formatting.
    
    Ensures that structured technical metadata (WHOIS, Org info) is correctly 
    transformed into a readable text format within the report.
    """
    report_path = tmp_path / "intel_report.txt"
    rep = Reporter(str(report_path), logger=None)

    # Mock data structure matching WhoisAnalyzer output
    intel_data: Dict[str, Any] = {
        'registrar': 'NameCheap',
        'org': 'CyberCorp',
        'name_servers': ['ns1.dns.com', 'ns2.dns.com'],
        'creation_date': '2020-01-01',
        'expiration_date': '2025-01-01'
    }

    # Execute write operation
    rep.write_intelligence("target.com", intel_data)
    
    content: str = report_path.read_text()

    # Section Header Validation
    assert "[+] DOMAIN INTELLIGENCE: target.com" in content
    
    # Key-Value Pair Validation
    assert "Registrar:" in content and "NameCheap" in content
    assert "Organization:" in content and "CyberCorp" in content
    assert "Creation:" in content and "2020-01-01" in content
    
    # List/Iterable Data Validation (NameServers)
    assert "ns1.dns.com" in content
    assert "ns2.dns.com" in content

def test_reporter_generic_section_logging(tmp_path: Any) -> None:
    """
    Test Case: Generic Section Writing.
    
    Verifies that 'write_section' correctly creates a new block for findings
    like subdomains or tech stacks with timestamps and total counts.
    """
    report_path = tmp_path / "section_test.txt"
    rep = Reporter(str(report_path), logger=None)
    
    findings: List[str] = ["api.test.com", "dev.test.com", "mail.test.com"]
    section_title: str = "Passive Subdomains"
    
    # Using 'write_section' as defined in your Reporter class
    rep.write_section(section_title, findings)
    
    content: str = report_path.read_text()
    
    # Title is forced to upper() in your code
    assert section_title.upper() in content
    assert "Timestamp:" in content
    assert "Total items in section: 3" in content
    
    for item in findings:
        assert item in content