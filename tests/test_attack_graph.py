"""Tests for the deterministic attack-path / entity graph."""

from src.attack_graph import build_attack_graph


def test_kill_chain_stages_in_order(events):
    g = build_attack_graph(events)
    stage_names = [s["stage"] for s in g["stages"]]
    # Key stages of the bundled campaign must be present and ordered.
    for stage in ("Initial Access", "Credential Access", "Command & Control", "Exfiltration"):
        assert stage in stage_names
    # The graph preserves kill-chain order.
    assert stage_names == sorted(stage_names, key=_stage_index)


def _stage_index(name):
    from src.attack_graph import STAGE_ORDER
    return STAGE_ORDER.index(name)


def test_entities_identified(events):
    ent = build_attack_graph(events)["entities"]
    assert "203.0.113.45" in ent["attacker"]
    assert "198.51.100.200" in ent["c2"]
    assert "svc_backup" in ent["accounts"]
    assert any(h in ("DC1", "websrv-01", "10.0.0.55") for h in ent["compromised"])


def test_every_stage_cites_evidence(events):
    for s in build_attack_graph(events)["stages"]:
        assert s["refs"], f"stage {s['stage']} has no evidence refs"
        assert all(r.startswith("EVT-") for r in s["refs"])
