# SAINT — Attack Chain Reconstruction

Reconstructs plausible multi-stage attack paths from noisy security events by:
1. scoring each event against **that entity's own prior behavior** (causal — no peeking at the future),
2. linking events into candidate chains via two relationship types:
   - **pivot**: A's target becomes B's actor (classic lateral movement) — loose time window (2h)
   - **same-actor**: same identity, different action shortly after — tight time window (70min), because on its own this is weak evidence
3. beam-searching for the highest-scoring, most entity-type-diverse chains, then deduping near-identical "stories."

## Run it
```
cd saint
pip install networkx flask
python3 app.py
```
Open http://localhost:5055 — pick a scenario from the dropdown top-right.

## Files
- `events.py` — synthetic event generator: background traffic, legit-but-unusual admin noise (the false-positive trap), and one embedded multi-stage attack (compromised login → recon → lateral move → priv-esc → sensitive access → exfil)
- `scoring.py` — per-entity causal baselines + anomaly scoring
- `chains.py` — successor graph + beam search chain reconstruction
- `app.py` — Flask API (`/api/summary`, `/api/chains`, `/api/graph`)
- `static/index.html` — UI
- `static_data.json` — precomputed scenarios (used by the standalone demo file, not the live app)

## For judges: what's real vs. what's a hackathon shortcut
- **Real**: the causal-baseline scoring, the pivot/same-actor chain linking logic, the beam search + dedup, and the fact that it's tested against a scenario deliberately built to include false-positive traps (ticketed admin perm-changes, off-hours maintenance).
- **Shortcut**: data is synthetic, not pulled from real SIEM/EDR logs — no ingestion connectors built. Baselines are simple frequency/novelty stats, not a trained model. Thresholds (`MIN_EDGE_SCORE`, window sizes) are hand-tuned against 4 seeds, not validated at scale.
- **Known limitation to mention if asked**: time-window-based pivot linking can still occasionally stitch in a coincidental hop (e.g., an unrelated login that happens to share a machine). Given more time: session/IP correlation instead of pure time windows, and a precision/recall eval harness across many random seeds instead of eyeballing 4.

## Talking points for the pitch
- The hard part of this problem is explicitly *not* "detect the anomaly" — individual events (a ticketed perm-change, an off-hours login) are legitimately noisy. The hard part is that a chain only becomes suspicious in combination, across entity boundaries, in a rising sequence. That's why chain reconstruction — not event-level flagging — is the core contribution.
- Every score is inspectable and explainable (behavioral rarity, action risk, boundary risk, ticket presence) — no black box, which matters for a SOC analyst who needs to justify escalation.
