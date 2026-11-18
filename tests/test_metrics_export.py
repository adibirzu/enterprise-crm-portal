"""Metrics stay on the Prometheus scrape endpoint; no OTLP metric export to APM.

The APM endpoint accepts traces but not OTLP metrics, so exporting metrics
there only produced failed requests.
"""

from __future__ import annotations

import dataclasses

import pytest

from server.observability import metrics as crm_metrics


class _RecordingProvider:
    def __init__(self, *, resource, metric_readers):
        self.resource = resource
        self.metric_readers = list(metric_readers)


def _use_apm(monkeypatch: pytest.MonkeyPatch, endpoint: str, datakey: str) -> None:
    replaced = dataclasses.replace(
        crm_metrics.cfg, oci_apm_endpoint=endpoint, oci_apm_private_datakey=datakey
    )
    monkeypatch.setattr(crm_metrics, "cfg", replaced)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[_RecordingProvider]:
    providers: list[_RecordingProvider] = []

    def _provider(**kwargs):
        provider = _RecordingProvider(**kwargs)
        providers.append(provider)
        return provider

    monkeypatch.setattr(crm_metrics, "MeterProvider", _provider)
    monkeypatch.setattr(crm_metrics.metrics, "set_meter_provider", lambda provider: None)
    monkeypatch.setattr(crm_metrics, "_initialized", False)
    monkeypatch.setattr(crm_metrics, "_meter", None)
    return providers


def test_apm_configured_does_not_add_an_otlp_metric_reader(
    monkeypatch: pytest.MonkeyPatch, recorded: list[_RecordingProvider]
) -> None:
    _use_apm(monkeypatch, "https://apm.example.invalid", "synthetic-datakey")
    assert crm_metrics.cfg.apm_configured

    crm_metrics.init_metrics()

    assert len(recorded) == 1
    reader_types = {type(reader).__name__ for reader in recorded[0].metric_readers}
    assert "PeriodicExportingMetricReader" not in reader_types
    assert reader_types == {"PrometheusMetricReader"}


def test_prometheus_reader_is_used_without_apm(
    monkeypatch: pytest.MonkeyPatch, recorded: list[_RecordingProvider]
) -> None:
    _use_apm(monkeypatch, "", "")

    crm_metrics.init_metrics()

    assert {type(r).__name__ for r in recorded[0].metric_readers} == {"PrometheusMetricReader"}


def test_startup_with_apm_keeps_metrics_prometheus_only(
    monkeypatch: pytest.MonkeyPatch, recorded: list[_RecordingProvider]
) -> None:
    """Drive the real startup order (init_otel then init_metrics) with APM set.

    Contract: traces go to APM, metrics go only to Prometheus. A wrong build
    installs an OTLP-exporting MeterProvider during init_otel, which then wins
    the global provider and starves the Prometheus scrape.
    """
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace

    from server.observability import otel_setup

    replaced = dataclasses.replace(
        otel_setup.cfg,
        oci_apm_endpoint="https://apm.example.invalid",
        oci_apm_private_datakey="synthetic-datakey",
        otlp_log_export_enabled=False,
    )
    monkeypatch.setattr(otel_setup, "cfg", replaced)
    monkeypatch.setattr(crm_metrics, "cfg", replaced)
    installed: list[object] = []
    monkeypatch.setattr(otel_metrics, "set_meter_provider", installed.append)
    monkeypatch.setattr(crm_metrics.metrics, "set_meter_provider", installed.append)
    monkeypatch.setattr(trace, "set_tracer_provider", lambda provider: None)
    monkeypatch.setattr(otel_setup, "_try_shared_init", lambda: False)

    otel_setup._standalone_init()
    crm_metrics.init_metrics()

    assert installed == recorded
    assert len(recorded) == 1
    assert {type(r).__name__ for r in recorded[0].metric_readers} == {"PrometheusMetricReader"}
