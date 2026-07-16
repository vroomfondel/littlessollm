"""Unit tests for littlessollm.config: secret-resolution precedence and mapping helpers."""

import os
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from littlessollm import config


@pytest.fixture(autouse=True)
def _reset_secret_cache() -> Iterator[None]:
    # module-level cache is keyed by (path, mtime), but reset explicitly so
    # tests never see another test's aggregated-secrets file.
    config._secrets_cache.data = None
    config._secrets_cache.mtime = None
    config._secrets_cache.path = None
    yield


def test_secret_file_wins_over_aggregated_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "OIDC_CLIENT_SECRET"
    secret_file.write_text("from-file\n")

    agg_file = tmp_path / "secrets.yaml"
    agg_file.write_text("OIDC_CLIENT_SECRET: from-aggregated\n")

    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("IDP_SECRETS_FILE", str(agg_file))
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "from-env")

    assert config.secret("OIDC_CLIENT_SECRET") == "from-file"


def test_secret_aggregated_wins_over_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agg_file = tmp_path / "secrets.yaml"
    agg_file.write_text("REDIS_URL: redis://from-aggregated:6379/0\n")

    monkeypatch.delenv("REDIS_URL_FILE", raising=False)
    monkeypatch.setenv("IDP_SECRETS_FILE", str(agg_file))
    monkeypatch.setenv("REDIS_URL", "redis://from-env:6379/0")

    assert config.secret("REDIS_URL") == "redis://from-aggregated:6379/0"


def test_secret_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOME_SECRET_FILE", raising=False)
    monkeypatch.delenv("IDP_SECRETS_FILE", raising=False)
    monkeypatch.setenv("SOME_SECRET", "env-value")

    assert config.secret("SOME_SECRET") == "env-value"


def test_secret_returns_default_when_nothing_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABSENT_SECRET_FILE", raising=False)
    monkeypatch.delenv("IDP_SECRETS_FILE", raising=False)
    monkeypatch.delenv("ABSENT_SECRET", raising=False)

    assert config.secret("ABSENT_SECRET", default="fallback") == "fallback"


def test_secret_required_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_SECRET_FILE", raising=False)
    monkeypatch.delenv("IDP_SECRETS_FILE", raising=False)
    monkeypatch.delenv("MISSING_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="MISSING_SECRET"):
        config.secret("MISSING_SECRET", required=True)


def test_secret_file_read_strips_trailing_newlines_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "s"
    secret_file.write_text("value\nwith\nnewlines-in-middle\n\n")
    monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))

    assert config.secret("MY_SECRET") == "value\nwith\nnewlines-in-middle"


def test_first_match_returns_first_key_in_priority_order() -> None:
    mapping = {"team-eng": ["engineers", "backend"], "team-data": ["data-science"]}

    assert config.first_match(mapping, {"data-science"}) == "team-data"
    assert config.first_match(mapping, {"engineers"}) == "team-eng"
    assert config.first_match(mapping, {"unrelated"}) is None
    # both groups present -> first mapping key wins (dict insertion order)
    assert config.first_match(mapping, {"backend", "data-science"}) == "team-eng"


def test_first_match_handles_empty_mapping() -> None:
    assert config.first_match({}, {"anything"}) is None
    assert config.first_match(None, {"anything"}) is None  # type: ignore[arg-type]


def test_get_config_loads_and_reloads_on_mtime_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "idp-mapping.yaml"
    cfg_file.write_text(
        textwrap.dedent(
            """
            oidc:
              issuer: https://idp.example.com/realms/one
            """
        )
    )
    monkeypatch.setattr(config, "CONFIG_PATH", str(cfg_file))
    config._mapping_cache.data = None
    config._mapping_cache.mtime = None

    assert config.oidc()["issuer"] == "https://idp.example.com/realms/one"

    cfg_file.write_text(
        textwrap.dedent(
            """
            oidc:
              issuer: https://idp.example.com/realms/two
            """
        )
    )
    # force a distinct mtime (some filesystems only have 1s resolution)
    new_mtime = cfg_file.stat().st_mtime + 5
    os.utime(cfg_file, (new_mtime, new_mtime))

    assert config.oidc()["issuer"] == "https://idp.example.com/realms/two"


def test_get_config_missing_file_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "does-not-exist.yaml"))
    with pytest.raises(RuntimeError, match="not readable"):
        config.get_config()


def test_ui_sso_and_api_auth_default_to_empty_dict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "idp-mapping.yaml"
    cfg_file.write_text("oidc:\n  issuer: https://idp.example.com\n")
    monkeypatch.setattr(config, "CONFIG_PATH", str(cfg_file))
    config._mapping_cache.data = None
    config._mapping_cache.mtime = None

    assert config.ui_sso() == {}
    assert config.api_auth() == {}
