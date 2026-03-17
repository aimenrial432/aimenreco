import os
import pytest
from aimenreco.utils.reporter import Reporter

def test_reporter_formatting(tmp_path):
    """
    Test Case: Content Integrity and Header Formatting.
    Checks if the Reporter correctly applies headers, uppercase titles, 
    and includes the results and timestamp in the output file.
    """
    report_file = tmp_path / "report.txt"
    rep = Reporter(str(report_file))
    
    data = ["finding.example.com", "secret_key_found"]
    rep.write_section("Unit Test Section", data)
    
    content = report_file.read_text()
    # Should be uppercase even if passed as lowercase
    assert "==== UNIT TEST SECTION ====" in content
    assert "Timestamp:" in content
    assert "finding.example.com" in content
    assert "secret_key_found" in content

def test_reporter_empty_data(tmp_path):
    """
    Test Case: Efficiency and File Avoidance.
    Ensures that no file is created or touched if the data list is empty,
    preventing cluttered empty reports on the user's disk.
    """
    report_file = tmp_path / "empty.txt"
    rep = Reporter(str(report_file))
    rep.write_section("Empty", [])
    
    assert not report_file.exists()

def test_reporter_append_mode(tmp_path):
    """
    Test Case: Result Persistence (Append Mode).
    Verifies that subsequent calls to write_section do not overwrite 
    previous results but append them, which is critical for multi-phase scans.
    """
    report_file = tmp_path / "persistence.txt"
    rep = Reporter(str(report_file))
    
    rep.write_section("Phase 1", ["result_a"])
    rep.write_section("Phase 2", ["result_b"])
    
    content = report_file.read_text()
    assert "PHASE 1" in content
    assert "PHASE 2" in content
    assert "result_a" in content
    assert "result_b" in content
    # Check that there are two distinct headers
    assert content.count("====") >= 4 

def test_reporter_no_output_flag(tmp_path):
    """
    Test Case: Graceful Handling of None Type.
    Ensures the reporter doesn't crash if the user didn't specify 
    an output file (-o), allowing the tool to run only in console mode.
    """
    # If args.output is None, the Reporter should just do nothing silently
    rep = Reporter(None)
    try:
        rep.write_section("Silent Mode", ["should_not_crash"])
    except Exception as e:
        pytest.fail(f"Reporter crashed when output_path was None: {e}")

def test_reporter_io_error_resilience(tmp_path):
    """
    Test Case: Error Handling for Restricted Directories.
    Verifies the reporter doesn't kill the whole scan if it encounters 
    a permission error, but instead logs the error (if a logger is provided).
    """
    # Simulate a path that is actually a directory (cannot write as file)
    restricted_path = tmp_path / "restricted_dir"
    restricted_path.mkdir()
    
    rep = Reporter(str(restricted_path))
    # This should not raise an unhandled exception that stops the tool
    rep.write_section("Test", ["data"])