"""Unit tests for littlessollm.entrypoint: file-secret materialization precedence."""

from pathlib import Path

import pytest

from littlessollm import entrypoint


def test_populate_env_from_named_file_wins(tmp_path: Path) -> None:
    key_file = tmp_path / "master.key"
    key_file.write_text("sk-from-file\n")

    env = {"LITELLM_MASTER_KEY_FILE": str(key_file), "LITELLM_MASTER_KEY": "sk-from-env"}
    populated = entrypoint.populate_env_from_secrets(env)

    assert env["LITELLM_MASTER_KEY"] == "sk-from-file"
    assert populated == {"LITELLM_MASTER_KEY": "LITELLM_MASTER_KEY_FILE"}


def test_populate_env_aggregated_fills_when_no_named_file(tmp_path: Path) -> None:
    agg = tmp_path / "secrets.yaml"
    agg.write_text("DATABASE_URL: postgresql://from-aggregated\n")

    env = {"IDP_SECRETS_FILE": str(agg)}
    populated = entrypoint.populate_env_from_secrets(env)

    assert env["DATABASE_URL"] == "postgresql://from-aggregated"
    assert populated == {"DATABASE_URL": "IDP_SECRETS_FILE"}


def test_populate_env_named_file_wins_over_aggregated(tmp_path: Path) -> None:
    key_file = tmp_path / "master.key"
    key_file.write_text("sk-from-named-file\n")
    agg = tmp_path / "secrets.yaml"
    agg.write_text("LITELLM_MASTER_KEY: sk-from-aggregated\n")

    env = {"LITELLM_MASTER_KEY_FILE": str(key_file), "IDP_SECRETS_FILE": str(agg)}
    populated = entrypoint.populate_env_from_secrets(env)

    assert env["LITELLM_MASTER_KEY"] == "sk-from-named-file"
    assert populated["LITELLM_MASTER_KEY"] == "LITELLM_MASTER_KEY_FILE"


def test_populate_env_leaves_env_untouched_when_no_file_present() -> None:
    env = {"LITELLM_MASTER_KEY": "sk-existing-default"}
    populated = entrypoint.populate_env_from_secrets(env)

    assert env["LITELLM_MASTER_KEY"] == "sk-existing-default"
    assert populated == {}


def test_populate_env_aggregated_respects_override_env_false(tmp_path: Path) -> None:
    agg = tmp_path / "secrets.yaml"
    agg.write_text("DATABASE_URL: postgresql://from-aggregated\n")

    env = {"IDP_SECRETS_FILE": str(agg), "DATABASE_URL": "postgresql://existing-env"}
    populated = entrypoint.populate_env_from_secrets(env, override_env=False)

    assert env["DATABASE_URL"] == "postgresql://existing-env"
    assert populated == {}


def test_populate_env_aggregated_overrides_env_by_default(tmp_path: Path) -> None:
    agg = tmp_path / "secrets.yaml"
    agg.write_text("DATABASE_URL: postgresql://from-aggregated\n")

    env = {"IDP_SECRETS_FILE": str(agg), "DATABASE_URL": "postgresql://existing-env"}
    populated = entrypoint.populate_env_from_secrets(env)  # override_env=True default

    assert env["DATABASE_URL"] == "postgresql://from-aggregated"
    assert populated == {"DATABASE_URL": "IDP_SECRETS_FILE"}


def test_populate_env_does_not_treat_idp_secrets_file_pointer_as_its_own_secret(tmp_path: Path) -> None:
    agg = tmp_path / "secrets.yaml"
    agg.write_text("FOO: bar\n")

    env = {"IDP_SECRETS_FILE": str(agg)}
    populated = entrypoint.populate_env_from_secrets(env)

    # Regression test: IDP_SECRETS_FILE is not a SECRET_BASE_NAMES entry, so
    # step 1 never looks it up as "IDP_SECRETS" in the first place; only the
    # aggregated YAML it points to (step 2) may populate env vars.
    assert "IDP_SECRETS" not in env
    assert env["FOO"] == "bar"
    assert populated == {"FOO": "IDP_SECRETS_FILE"}


def test_populate_env_warns_but_does_not_raise_on_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = {"LITELLM_MASTER_KEY_FILE": str(tmp_path / "does-not-exist")}
    populated = entrypoint.populate_env_from_secrets(env)

    assert populated == {}
    assert "LITELLM_MASTER_KEY" not in env
    assert "file missing" in capsys.readouterr().err


def test_populate_env_ignores_unrelated_file_suffixed_vars(tmp_path: Path) -> None:
    # Regression test for a real bug: base images commonly set their own
    # unrelated *_FILE vars (e.g. SSL_CERT_FILE -> a CA bundle path). A
    # blind scan over all env vars ending in _FILE would treat "SSL_CERT"
    # as a secret, read the (often large) CA bundle into it, and can crash
    # the exec'd child with "Argument list too long" once the env grows
    # past ARG_MAX. Only known SECRET_BASE_NAMES may be materialized.
    ca_bundle = tmp_path / "ca-bundle.crt"
    ca_bundle.write_text("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")

    env = {"SSL_CERT_FILE": str(ca_bundle)}
    populated = entrypoint.populate_env_from_secrets(env)

    assert "SSL_CERT" not in env
    assert populated == {}


def test_secret_base_names_includes_defaults_and_extends_via_env() -> None:
    env: dict[str, str] = {}
    assert entrypoint.secret_base_names(env) == list(entrypoint.DEFAULT_SECRET_BASE_NAMES)

    env = {"SECRET_BASE_NAMES": "MY_EXTRA_SECRET, LITELLM_MASTER_KEY"}
    names = entrypoint.secret_base_names(env)
    assert "MY_EXTRA_SECRET" in names
    assert names.count("LITELLM_MASTER_KEY") == 1  # de-duplicated


def test_populate_env_honors_extra_secret_base_names(tmp_path: Path) -> None:
    key_file = tmp_path / "extra.secret"
    key_file.write_text("extra-value\n")

    env = {"SECRET_BASE_NAMES": "MY_EXTRA_SECRET", "MY_EXTRA_SECRET_FILE": str(key_file)}
    populated = entrypoint.populate_env_from_secrets(env)

    assert env["MY_EXTRA_SECRET"] == "extra-value"
    assert populated == {"MY_EXTRA_SECRET": "MY_EXTRA_SECRET_FILE"}


def test_missing_required_reports_unresolved_only() -> None:
    env = {"A": "1", "B": ""}
    assert entrypoint.missing_required(env, ["A", "B", "C"]) == ["B", "C"]
    assert entrypoint.missing_required(env, []) == []


def test_load_aggregated_secrets_missing_path_returns_empty() -> None:
    assert entrypoint.load_aggregated_secrets(None) == {}
    assert entrypoint.load_aggregated_secrets("/no/such/file.yaml") == {}


def test_load_aggregated_secrets_unparsable_file_warns_and_returns_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "secrets.yaml"
    bad.write_text(":::not: valid: yaml:::\n- [unterminated")

    assert entrypoint.load_aggregated_secrets(str(bad)) == {}
    assert "unparsable" in capsys.readouterr().err


def test_resolve_command_prefers_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LITELLM_START_CMD", raising=False)
    assert entrypoint.resolve_command(["litellm", "--port", "1234"]) == ["litellm", "--port", "1234"]


def test_resolve_command_falls_back_to_litellm_start_cmd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITELLM_START_CMD", "uvicorn littlessollm.asgi:app --port 9000")
    assert entrypoint.resolve_command([]) == ["uvicorn", "littlessollm.asgi:app", "--port", "9000"]


def test_resolve_command_default_when_nothing_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LITELLM_START_CMD", raising=False)
    assert entrypoint.resolve_command([]) == [
        "uvicorn",
        "littlessollm.asgi:app",
        "--host",
        "0.0.0.0",
        "--port",
        "4000",
    ]
