from src.password_checker import check_password


def test_common_password_is_weak():
    result = check_password("password")
    assert result["verdict"] == "weak"
    assert result["checks"]["not_common"] is False


def test_short_password_is_weak():
    result = check_password("Ab1!")
    assert result["verdict"] == "weak"
    assert result["checks"]["min_length"] is False


def test_strong_password_passes_all_checks():
    result = check_password("Correct-Horse-Battery-Staple-9!")
    assert result["verdict"] == "strong"
    assert all(result["checks"].values())


def test_moderate_password_missing_one_category():
    result = check_password("longpassphrasewithoutdigits!!")
    assert result["verdict"] in ("moderate", "weak")
    assert result["checks"]["has_digit"] is False
