from src.parsers.ua_analysis import detect_suspicious_user_agent


def test_detect_suspicious_user_agent_positive():
    ok, pat = detect_suspicious_user_agent("sqlmap/1.5.0")
    assert ok is True
    assert pat


def test_detect_suspicious_user_agent_negative():
    ok, pat = detect_suspicious_user_agent("Mozilla/5.0 (Windows NT 10.0)")
    assert ok is False
    assert pat is None

