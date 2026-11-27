import re
from pathlib import Path


def test_checkout_handoff_records_stable_ownership_contract():
    handoff = (Path(__file__).resolve().parents[1] / 'docs/checkout-ownership.md').read_text()
    assert not re.search(r'[0-9a-fA-F]{40}', handoff)
    assert 'standalone CRM repository as the canonical source' in handoff
    assert 'external-projects.yaml' in handoff
    assert 'source of truth for the CRM pin' in handoff
    assert 'umbrella owner' in handoff
    assert 'refresh' in handoff
    assert 'receipt' in handoff
    assert '/api/integrations/schema' in handoff
