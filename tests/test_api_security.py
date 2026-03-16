"""Tests for API security: path traversal prevention and SQL query restrictions."""
import pytest
import os
import re

# Import the security helpers from app module
from modules.ui.security import _SQL_FORBIDDEN_PATTERNS


class TestSQLForbiddenPatterns:
    """Test the SQL query restriction regex."""

    def test_select_allowed(self):
        """Plain SELECT queries should not match forbidden patterns."""
        safe_queries = [
            "SELECT * FROM images",
            "SELECT id, file_path FROM images WHERE rating > 3",
            "SELECT COUNT(*) FROM images",
            "SELECT * FROM images ORDER BY score_general DESC",
        ]
        for q in safe_queries:
            assert not _SQL_FORBIDDEN_PATTERNS.search(q), f"Safe query wrongly blocked: {q}"

    def test_dml_blocked(self):
        """DML keywords should be caught by the forbidden pattern."""
        dangerous_queries = [
            "SELECT 1; INSERT INTO images VALUES (1)",
            "SELECT * FROM images; DELETE FROM images",
            "SELECT * FROM images; DROP TABLE images",
            "SELECT * FROM images; ALTER TABLE images ADD x INT",
            "SELECT * FROM images; CREATE TABLE evil (id INT)",
            "SELECT 1; UPDATE images SET rating=0",
            "SELECT * INTO outfile FROM images",
            "SELECT 1; EXECUTE PROCEDURE foo",
            "SELECT 1; GRANT ALL ON images TO public",
            "SELECT 1; REVOKE ALL ON images FROM public",
        ]
        for q in dangerous_queries:
            assert _SQL_FORBIDDEN_PATTERNS.search(q), f"Dangerous query not blocked: {q}"

    def test_case_insensitive(self):
        """Pattern should match regardless of case."""
        assert _SQL_FORBIDDEN_PATTERNS.search("select * from images; drop table images")
        assert _SQL_FORBIDDEN_PATTERNS.search("SELECT * FROM images; Drop Table images")

    def test_select_into_blocked(self):
        """SELECT INTO should be blocked by the INTO keyword."""
        assert _SQL_FORBIDDEN_PATTERNS.search("SELECT * INTO temp FROM images")


class TestPathValidation:
    """Test the path traversal prevention logic."""

    def test_dotdot_rejected(self):
        """Paths with .. should be rejected."""
        from fastapi import HTTPException
        from modules.ui.security import _validate_file_path

        with pytest.raises(HTTPException) as exc_info:
            _validate_file_path("../../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_dotdot_in_middle_rejected(self):
        """Paths with embedded .. should be rejected."""
        from fastapi import HTTPException
        from modules.ui.security import _validate_file_path

        with pytest.raises(HTTPException) as exc_info:
            _validate_file_path("D:/Photos/../../../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_allowed_root_exact_match(self, tmp_path, monkeypatch):
        """Exact root path should be allowed."""
        from modules.ui import security

        root = tmp_path / "allowed"
        root.mkdir()

        monkeypatch.setattr(security, "_ALLOWED_IMAGE_ROOTS", [str(root)])

        assert security._validate_file_path(str(root)) == os.path.realpath(str(root))

    def test_allowed_root_nested_child(self, tmp_path, monkeypatch):
        """Child path under allowed root should be allowed."""
        from modules.ui import security

        root = tmp_path / "allowed"
        child = root / "nested" / "image.jpg"
        child.parent.mkdir(parents=True)
        child.touch()

        monkeypatch.setattr(security, "_ALLOWED_IMAGE_ROOTS", [str(root)])

        assert security._validate_file_path(str(child)) == os.path.realpath(str(child))

    def test_shared_prefix_sibling_rejected(self, tmp_path, monkeypatch):
        """Sibling with shared prefix (bar2) must not match root (bar)."""
        from fastapi import HTTPException
        from modules.ui import security

        root = tmp_path / "foo" / "bar"
        sibling = tmp_path / "foo" / "bar2" / "image.jpg"
        root.mkdir(parents=True)
        sibling.parent.mkdir(parents=True)
        sibling.touch()

        monkeypatch.setattr(security, "_ALLOWED_IMAGE_ROOTS", [str(root)])

        with pytest.raises(HTTPException) as exc_info:
            security._validate_file_path(str(sibling))
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Access denied"

    def test_symlink_resolved_path_allowed(self, tmp_path, monkeypatch):
        """Symlink paths should be validated against their resolved location."""
        from modules.ui import security

        root = tmp_path / "allowed"
        target = root / "images" / "sample.jpg"
        link = tmp_path / "link.jpg"
        target.parent.mkdir(parents=True)
        target.touch()
        link.symlink_to(target)

        monkeypatch.setattr(security, "_ALLOWED_IMAGE_ROOTS", [str(root)])

        assert security._validate_file_path(str(link)) == os.path.realpath(str(target))


class TestRateLimit:
    """Test the rate limiting logic."""

    def test_rate_limit_allows_initial_requests(self):
        """First few requests should pass."""
        from modules.ui.security import _check_rate_limit, _rate_limits
        # Clear state
        _rate_limits.clear()
        # Should not raise
        _check_rate_limit("test_endpoint")

    def test_rate_limit_blocks_excess_requests(self):
        """Excess requests within window should be blocked."""
        from fastapi import HTTPException
        from modules.ui.security import _check_rate_limit, _rate_limits, _RATE_LIMIT_MAX_REQUESTS
        # Clear state
        _rate_limits.clear()

        # Fill up the limit
        for _ in range(_RATE_LIMIT_MAX_REQUESTS):
            _check_rate_limit("test_endpoint_flood")

        # Next one should fail
        with pytest.raises(HTTPException) as exc_info:
            _check_rate_limit("test_endpoint_flood")
        assert exc_info.value.status_code == 429
