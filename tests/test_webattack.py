"""Offline tests for the Web Attack Toolkit."""

from webattack import sqli, xss, fingerprint, dirbrute


def test_sqli_error_regex_matches_many_dbs():
    samples = [
        "You have an error in your SQL syntax near '1'",       # MySQL
        "Warning: mysqli_query() failed",                       # MySQL
        "ORA-01756: quoted string not properly terminated",     # Oracle
        "PostgreSQL query failed: ERROR: near",                 # PostgreSQL
        "syntax error at or near \"'\"",                        # PostgreSQL
        "Microsoft OLE DB Provider for SQL Server error",       # MSSQL
        "Incorrect syntax near ')'",                            # MSSQL
        "sqlite3.OperationalError: near syntax error",          # SQLite
        "SQLSTATE[42000]: Syntax error",                        # PDO/generic
    ]
    for s in samples:
        assert sqli.DB_ERRORS.search(s), s
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
