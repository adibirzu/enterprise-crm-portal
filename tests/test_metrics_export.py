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

