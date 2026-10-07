"""Contrats de déploiement vérifiés sans démarrer de conteneur ni lire de secret réel."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


@pytest.fixture
def composition(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose CLI absent")
    source = tmp_path / "source"
    source.mkdir()
    (source / ".env").write_text("PRIVASOC_API_TOKEN=test-ingest\n", encoding="utf-8")
    env_file = tmp_path / "deployment.env"
    env_file.write_text(
        f"PRIVASOC_DIR={source.as_posix()}\nSOVGATE_DIR={source.as_posix()}\n"
        "PRIVASOC_API_TOKEN=test-ingest\nSOVGATE_PRIVASOC_KEY=test-client\n"
        "SOVGATE_HMAC_SECRET=test-hmac-for-compose\nEXTERNAL_API_KEY=test-provider\n"
        "FRONTIER_MODEL=frontier-test\n",
        encoding="utf-8",
    )
    names = {
        "PRIVASOC_DIR",
        "SOVGATE_DIR",
        "PRIVASOC_API_TOKEN",
        "SOVGATE_PRIVASOC_KEY",
        "SOVGATE_HMAC_SECRET",
        "EXTERNAL_API_KEY",
        "FRONTIER_MODEL",
        "LOCAL_MODEL",
        "OLLAMA_IMAGE",
        "PRIVASOC_BIND",
        "SYSLOG_BIND",
    }
    env = {k: v for k, v in os.environ.items() if k not in names}

    def load(frontier=False):
        args = ["docker", "compose", "--env-file", str(env_file)]
        if frontier:
            args += ["--profile", "frontier"]
        args += ["-f", str(DEPLOY / "docker-compose.yml")]
        if frontier:
            args += ["-f", str(DEPLOY / "compose.frontier.yml")]
        args += ["config", "--format", "json"]
        result = subprocess.run(
            args, env=env, capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return load


def test_local_default_has_no_remote_endpoint(composition):
    config = composition()
    services = config["services"]
    assert "sovgate" not in services
    assert services["privasoc"]["environment"]["PRIVASOC_LLM_REMOTE_URL"] == ""
    assert services["privasoc"]["environment"]["PRIVASOC_LLM_REMOTE_API_KEY"] == ""
    assert services["privasoc"]["environment"]["PRIVASOC_AUTO_FALLBACK"] == "false"
    assert services["privasoc"]["environment"]["PRIVASOC_REMOTE_RESIDUAL_PASS"] == "true"


def test_networks_and_secrets_are_separated(composition):
    config = composition(True)
    services, networks = config["services"], config["networks"]
    assert all(networks[n]["internal"] for n in services["privasoc"]["networks"])
    assert set(services["vector"]["networks"]) == {"ingest"}
    assert set(services["sovgate"]["networks"]) == {"gateway-link", "frontier-egress"}
    assert "ports" not in services["sovgate"] and "ports" not in services["local-model"]
    assert set(services["vector"]["environment"]) == {
        "PRIVASOC_INGEST_URL",
        "PRIVASOC_API_TOKEN",
    }
    assert "EXTERNAL_API_KEY" not in services["privasoc"]["environment"]
    for name in ("vector", "privasoc"):
        assert all(p["host_ip"] == "127.0.0.1" for p in services[name]["ports"])


def test_frontier_uses_ner_and_the_same_effective_model(composition):
    config = composition(True)
    services = config["services"]
    remote = services["sovgate"]["environment"]
    assert remote["SOVGATE_NER_BACKEND"] == "gliner"
    assert services["sovgate"]["build"]["args"]["EXTRAS"] == "ner"
    assert (
        remote["SOVGATE_EXTERNAL_MODEL"]
        == services["privasoc"]["environment"]["PRIVASOC_LLM_REMOTE_MODEL"]
    )
    assert (
        services["privasoc"]["depends_on"]["sovgate"]["condition"] == "service_healthy"
    )
