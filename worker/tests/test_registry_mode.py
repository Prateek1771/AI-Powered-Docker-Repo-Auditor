import asyncio

import pytest

from app.processors.layers import extract_layers
from app.processors.profile import build_profile
from app.scanners import trivy
from app.scanners.docker_history import DockerHistoryError, history_from_report
from app.scanners.image_inspect import inspect_from_report

# Shaped from a real `trivy image --format json` run. The three parts that
# matter: history is oldest-first and includes steps that made no layer,
# rootfs.diff_ids lists only the steps that did, and Metadata.Layers carries
# the size for each of those.
REPORT = {
    "Metadata": {
        "Size": 200,
        "ImageID": "sha256:image",
        "RepoTags": ["demo:latest"],
        "OS": {"Family": "debian", "Name": "13.2"},
        "Layers": [
            {"DiffID": "sha256:aaa", "Size": 120},
            {"DiffID": "sha256:bbb", "Size": 80},
        ],
        "ImageConfig": {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"diff_ids": ["sha256:aaa", "sha256:bbb"]},
            "config": {
                "User": "worker",
                "Env": ["PATH=/usr/bin", "LANG=C.UTF-8"],
                "ExposedPorts": {"8080/tcp": {}},
                "Cmd": ["python", "-m", "app.main"],
                "Healthcheck": {"Test": ["CMD", "true"]},
            },
            "history": [
                {"created_by": "FROM debian:13-slim"},
                {"created_by": "ENV LANG=C.UTF-8", "empty_layer": True},
                {"created_by": "RUN /bin/sh -c apt-get install -y curl"},
            ],
        },
    }
}


class TestHistoryFromReport:
    def test_each_step_gets_the_size_of_the_layer_it_produced(self):
        # Newest-first, like the CLI prints it.
        entries = history_from_report(REPORT)

        assert [e["Size"] for e in entries] == ["80B", "0B", "120B"]

    def test_an_env_line_is_empty_even_though_a_real_layer_can_be_tiny(self):
        # Size alone cannot tell these apart, which is why the entry carries
        # the flag the image config already knows.
        entries = history_from_report(REPORT)

        assert [e["EmptyLayer"] for e in entries] == [False, True, False]

    def test_layers_come_out_oldest_first_with_the_base_at_index_zero(self):
        layers = extract_layers(history_from_report(REPORT))

        assert [layer.index for layer in layers] == [0, 1, 2]
        assert layers[0].command == "FROM debian:13-slim"
        assert layers[0].size_bytes == 120
        assert layers[1].is_empty is True
        assert layers[2].command == "RUN apt-get install -y curl"

    def test_a_report_without_history_is_an_error_not_an_empty_scan(self):
        # Silently returning [] would make bloat_detective report
        # skipped_no_input, which reads as "nothing to fix".
        with pytest.raises(DockerHistoryError):
            history_from_report({"Metadata": {"ImageConfig": {}}})

    def test_more_steps_than_layers_does_not_shift_every_size(self):
        broken = {
            "Metadata": {
                "Layers": [{"DiffID": "sha256:aaa", "Size": 120}],
                "ImageConfig": {
                    "rootfs": {"diff_ids": ["sha256:aaa"]},
                    "history": [
                        {"created_by": "FROM x"},
                        {"created_by": "RUN y"},
                    ],
                },
            }
        }

        entries = history_from_report(broken)

        # The surplus step reports 0 rather than borrowing another step's size.
        assert [e["Size"] for e in entries] == ["0B", "120B"]


class TestInspectFromReport:
    def test_the_config_lands_where_build_profile_looks_for_it(self):
        inspect = inspect_from_report(REPORT)

        profile = build_profile(
            "demo:latest",
            inspect,
            REPORT,
            extract_layers(history_from_report(REPORT)),
        )

        assert profile.user == "worker"
        assert profile.has_healthcheck is True
        assert profile.exposed_ports == [8080]
        assert profile.os_family == "debian"
        assert profile.base_reference == "debian:13-slim"

    def test_a_report_without_a_config_is_an_error(self):
        with pytest.raises(DockerHistoryError):
            inspect_from_report({"Metadata": {}})


class TestScannerMode:
    def test_socket_mode_runs_trivy_as_a_sibling_container(self, monkeypatch):
        monkeypatch.setattr(trivy, "SCANNER_MODE", "socket")

        command = trivy.build_command("demo:latest")

        assert command[:2] == ["docker", "run"]
        assert "/var/run/docker.sock:/var/run/docker.sock" in command

    def test_registry_mode_calls_the_binary_with_no_socket(self, monkeypatch):
        monkeypatch.setattr(trivy, "SCANNER_MODE", "registry")

        command = trivy.build_command("demo:latest")

        assert command[0] == "trivy"
        assert not any("docker.sock" in part for part in command)
        assert command[-1] == "demo:latest"


class TestSingleFlight:
    async def test_concurrent_callers_share_one_trivy_run(self, monkeypatch):
        # The orchestrator gathers all three scanners at once, and in registry
        # mode all three want this report. Running Trivy three times over the
        # same image would triple the slowest step in the scan.
        calls = []

        async def fake(target: str) -> dict:
            calls.append(target)

            await asyncio.sleep(0.01)

            return REPORT

        monkeypatch.setattr(trivy, "_execute", fake)

        results = await asyncio.gather(
            trivy.image_report("demo:latest"),
            trivy.image_report("demo:latest"),
            trivy.image_report("demo:latest"),
        )

        assert calls == ["demo:latest"]
        assert all(result is REPORT for result in results)

    async def test_a_later_scan_of_the_same_tag_runs_again(self, monkeypatch):
        # The whole point of not caching: an image rebuilt under the same tag
        # must not be reported from the pre-rebuild run.
        calls = []

        async def fake(target: str) -> dict:
            calls.append(target)

            return REPORT

        monkeypatch.setattr(trivy, "_execute", fake)

        await trivy.image_report("demo:latest")
        await trivy.image_report("demo:latest")

        assert calls == ["demo:latest", "demo:latest"]

    async def test_a_failure_is_not_held_against_the_next_caller(self, monkeypatch):
        attempts = []

        async def fake(target: str) -> dict:
            attempts.append(target)

            if len(attempts) == 1:
                raise trivy.TrivyScanError("boom")

            return REPORT

        monkeypatch.setattr(trivy, "_execute", fake)

        with pytest.raises(trivy.TrivyScanError):
            await trivy.image_report("demo:latest")

        assert await trivy.image_report("demo:latest") is REPORT


class TestPermanentFlag:
    def test_a_non_zero_trivy_exit_is_marked_permanent(self):
        try:
            raise trivy.TrivyScanError("Trivy exited 1: no such image", permanent=True)
        except trivy.TrivyScanError as exc:
            assert exc.permanent is True

    def test_a_trivy_scan_error_defaults_to_not_permanent(self):
        exc = trivy.TrivyScanError("Trivy scan timed out after 600s")

        assert exc.permanent is False

    def test_a_failed_pull_is_marked_permanent(self):
        exc = DockerHistoryError(
            "Could not pull demo:missing: manifest unknown", permanent=True
        )

        assert exc.permanent is True

    def test_a_malformed_report_defaults_to_not_permanent(self):
        with pytest.raises(DockerHistoryError) as exc_info:
            history_from_report({"Metadata": {"ImageConfig": {}}})

        assert exc_info.value.permanent is False
