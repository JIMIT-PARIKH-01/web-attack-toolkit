"""Offline tests for the Web Attack Toolkit."""

from webattack import sqli, xss, fingerprint, dirbrute


def test_sqli_error_regex_matches():
    assert sqli.DB_ERRORS.search("You have an error in your SQL syntax near '1'")
    assert sqli.DB_ERRORS.search("Warning: mysqli_query() failed")
    assert not sqli.DB_ERRORS.search("a perfectly normal web page")


def test_sqli_has_payloads():
    assert "'" in sqli.PAYLOADS and len(sqli.PAYLOADS) >= 4


def test_xss_marker_in_payloads():
    assert any(xss._MARKER in p for p in xss.PAYLOADS)


def test_fingerprint_signatures():
    assert fingerprint.BODY_SIGNATURES["WordPress"].search("/wp-content/themes/x")
    assert fingerprint.BODY_SIGNATURES["Django"].search("csrfmiddlewaretoken=abc")
    assert not fingerprint.BODY_SIGNATURES["WordPress"].search("nothing here")


def test_dirbrute_wordlist_nonempty():
    assert len(dirbrute.COMMON_PATHS) > 20
    assert "robots.txt" in dirbrute.COMMON_PATHS
