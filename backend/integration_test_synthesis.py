"""
integration_test_synthesis.py
------------------------------
Integration test for SynthesisAgent — Phase 4 pipeline.
Run with: python integration_test_synthesis.py
Backend must be running on port 8001.
"""

import httpx
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8001"
TIMEOUT = 360.0


def divider(title=""):
    print(f"\n{'='*60}")
    if title:
        print(f"  {title}")
        print(f"{'='*60}")


def run_test(label: str, trigger: str, investigation_id: str) -> dict:
    divider(label)
    print(f"trigger: {trigger[:80]}...")
    print(f"investigation_id: {investigation_id}")
    print("Sending request...")

    start = time.time()
    try:
        r = httpx.post(
            f"{BASE_URL}/api/investigate",
            json={"trigger": trigger, "investigation_id": investigation_id},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
    except Exception as e:
        print(f"ERROR: {e}")
        return {}
    elapsed = time.time() - start
    print(f"Elapsed: {elapsed:.1f}s")
    return r.json()


def report_apt(result: dict):
    fr = result.get("final_report", {})

    if not fr:
        print("WARNING: final_report is EMPTY")
        return

    print(f"\nclassification     : {fr.get('classification')}")
    print(f"severity           : {fr.get('severity')}")
    print(f"generated_at       : {fr.get('generated_at')}")

    print("\n--- executive_summary ---")
    print(fr.get("executive_summary", "(empty)"))

    print("\n--- attack_overview ---")
    print(fr.get("attack_overview", "(empty)"))

    findings = fr.get("key_findings", [])
    print(f"\n--- key_findings ({len(findings)}) ---")
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] source={f.get('source')} | confidence={f.get('confidence')}")
        print(f"       finding : {f.get('finding')}")
        print(f"       evidence: {f.get('evidence')}")

    actions = fr.get("recommended_actions", [])
    print(f"\n--- recommended_actions ({len(actions)}) ---")
    for a in actions:
        print(f"  [{a.get('priority')}] {a.get('action')}")
        print(f"       mitre_technique: {a.get('mitre_technique')}")
        print(f"       rationale      : {a.get('rationale')[:120]}")

    techniques = fr.get("mitre_techniques_used", [])
    print(f"\n--- mitre_techniques_used ({len(techniques)}) ---")
    print("  " + ", ".join(techniques) if techniques else "  (none)")

    cves = fr.get("cves_identified", [])
    print(f"\n--- cves_identified ({len(cves)}) ---")
    print("  " + ", ".join(cves) if cves else "  (none)")

    print(f"\n--- investigation_confidence ---")
    print(f"  {fr.get('investigation_confidence')}")

    print("\n--- rag_sources_used ---")
    print(json.dumps(fr.get("rag_sources_used", {}), indent=4))

    print("\n--- threat_actor_profile ---")
    print(fr.get("threat_actor_profile", "(empty)"))


def report_unknown(result: dict):
    fr = result.get("final_report", {})
    classification = result.get("attack_classification", "N/A")
    print(f"\nclassification : {classification}")
    print(f"final_report empty : {not bool(fr)}")
    if fr:
        print(f"WARNING: SynthesisAgent ran on UNKNOWN — this is a BUG")
        print(json.dumps(fr, indent=2)[:500])
    else:
        print("OK — SynthesisAgent correctly skipped for UNKNOWN classification")


if __name__ == "__main__":
    suffix = datetime.now().strftime("%H%M%S")

    # ── Test 1: APT full pipeline ─────────────────────────────────────────
    apt_result = run_test(
        label="TEST 1 — APT Full Pipeline (Synthesis)",
        trigger=(
            "Suspicious outbound requests to AWS metadata endpoint detected "
            "from internal web server. Possible SSRF attack leading to IAM "
            "credential exposure."
        ),
        investigation_id=f"synthesis-apt-{suffix}",
    )
    report_apt(apt_result)

    # ── Test 2: UNKNOWN — should NOT reach SynthesisAgent ─────────────────
    unknown_result = run_test(
        label="TEST 2 — UNKNOWN (should NOT reach SynthesisAgent)",
        trigger="Alert fired. Please investigate immediately.",
        investigation_id=f"synthesis-unknown-{suffix}",
    )
    report_unknown(unknown_result)

    divider("DONE")
