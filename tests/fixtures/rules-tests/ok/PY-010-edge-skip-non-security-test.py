# PY-010 EDGE/SAFE: @pytest.mark.skip on a NON-security test — should NOT fire
# The rule requires the function name to match security-related regex
import pytest
import time


@pytest.mark.skip(reason="Slow integration test — run separately with --integration flag")
def test_data_export_performance():
    """Test that bulk data export completes within 30 seconds."""
    # This test is skipped but the name doesn't match the security regex
    start = time.time()
    # ... export 100k rows ...
    elapsed = time.time() - start
    assert elapsed < 30.0, f"Export too slow: {elapsed:.1f}s"


@pytest.mark.skip(reason="Flaky in CI due to external service dependency")
def test_email_delivery():
    """Test that email delivery completes successfully."""
    # This is an infrastructure test, not a security test
    # No keywords: auth, permission, security, token, etc.
    pass


@pytest.mark.skip(reason="UI test requires Selenium driver not installed in CI")
def test_dashboard_rendering():
    """Test that the dashboard renders all widgets correctly."""
    pass
