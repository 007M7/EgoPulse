from worker import health


def test_health_is_explicitly_non_operational() -> None:
    assert health() == {
        "worker": "foundation-probe",
        "status": "foundation-only",
    }
