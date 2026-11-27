from pathlib import Path


def test_checkout_handoff_records_source_and_umbrella_pin():
    handoff = Path('docs/checkout-ownership.md').read_text()
    assert '90da4e31dbb2eeba8fd1c8d51c8f8df48b927561' in handoff
    assert '65d5cdcb449f38d7e31d6ed825942c3d5b273c77' in handoff
    assert '/api/integrations/schema' in handoff
