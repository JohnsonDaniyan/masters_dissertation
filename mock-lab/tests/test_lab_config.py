from app.config import parse_env_toggles, settings, write_env_toggle


def test_write_env_toggle_preserves_comment(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("METADATA_ENABLED=true ##true\nPAR_ENFORCED=true\n")
    monkeypatch.setattr("app.config.ENV_PATH", env_path)
    previous = settings.METADATA_ENABLED

    try:
        write_env_toggle("METADATA_ENABLED", False)

        text = env_path.read_text()
        assert "METADATA_ENABLED=false ##true" in text
        assert settings.METADATA_ENABLED is False
        assert parse_env_toggles()["METADATA_ENABLED"] is False
        assert parse_env_toggles()["PAR_ENFORCED"] is True
    finally:
        settings.METADATA_ENABLED = previous
