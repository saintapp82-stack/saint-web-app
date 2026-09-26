"""
Graph construction + attack chain reconstruction.

Approach:
  1. Build a directed multigraph: nodes = entities, edges = scored events.
  2. Build a "temporal successor" index: event B can follow event A in a chain
     iff they share an entity (A.target == B.actor, or A.actor == B.actor, or
     A.target == B.target) AND 0 < B.ts - A.ts <= MAX_GAP_SECONDS.
     This is what turns disconnected log lines into a *path*.
  3. DFS/beam search over that successor graph, extending a chain only while
     it keeps looking like a rising attack story: cumulative suspicion grows,
     length is bounded, and we prefer chains that cross entity-type boundaries
     (user -> account -> service) over chains that loop within one entity type
     (which is usually just routine multi-step admin work).
  4. Rank resulting chains by a composite score; return top-K, deduplicated.
"""
import networkx as nx
from collections import defaultdict

from events import entity_type
from scoring import score_all

PIVOT_GAP_SECONDS = 2 * 3600     # "A's target becomes B's actor" (a real pivot) can be loose in time
SAME_ACTOR_GAP_SECONDS = 70 * 60 # "same actor, different action" must be tight -- otherwise it's just
                                  # someone's ordinary day, not a rush of attack steps
MIN_EDGE_SCORE = 0.6           # ignore near-baseline events as chain links
MAX_CHAIN_LEN = 6
BEAM_WIDTH = 25                # keep search tractable
MIN_CHAIN_SCORE = 2.5          # floor for something worth surfacing


def build_entity_graph(scored_events):
    """Simple directed multigraph for visualization: entities -> entities."""
    G = nx.MultiDiGraph()
    for e, s in scored_events:
        G.add_node(e.actor, type=entity_type(e.actor))
        G.add_node(e.target, type=entity_type(e.target))
        G.add_edge(e.actor, e.target, event=e, score=s, key=e.id)
    return G


def _link_kind(a, b):
    """
    Returns a string describing why b could follow a, or None if unrelated.
      "pivot"       -- a's target is b's actor: attacker just touched X, now acts as/from X.
                       This is the classic lateral-movement signature and gets a loose time window.
      "same_actor"  -- same identity doing a different thing shortly after. Weak evidence on its
                       own (could just be someone's ordinary day) so it needs a tight time window.
    """
    if a.target == b.actor:
        return "pivot"
    if a.actor == b.actor:
        return "same_actor"
    return None


def build_successor_index(scored_events):
    """
    For each event, precompute which later events could plausibly continue
    a chain from it, using the appropriate time window for the relationship
    type (pivot vs. same-actor), and only above the noise floor.
    """
    events_sorted = sorted(scored_events, key=lambda pair: pair[0].ts)
    n = len(events_sorted)
    successors = defaultdict(list)
    max_window = max(PIVOT_GAP_SECONDS, SAME_ACTOR_GAP_SECONDS)
    # simple O(n * window) scan; fine for hackathon-scale event volumes
    for i in range(n):
        e_i, s_i = events_sorted[i]
        if s_i < MIN_EDGE_SCORE:
            continue
        for j in range(i + 1, n):
            e_j, s_j = events_sorted[j]
            gap = e_j.ts - e_i.ts
            if gap > max_window:
                break
            if gap <= 0:
                continue
            if s_j < MIN_EDGE_SCORE:
                continue
            kind = _link_kind(e_i, e_j)
            if kind == "pivot" and gap <= PIVOT_GAP_SECONDS:
                successors[e_i.id].append((e_j, s_j))
            elif kind == "same_actor" and gap <= SAME_ACTOR_GAP_SECONDS:
                successors[e_i.id].append((e_j, s_j))
    return successors, {e.id: (e, s) for e, s in events_sorted}


def _chain_type_diversity(chain):
    types = {entity_type(e.actor) for e, _ in chain} | {entity_type(e.target) for e, _ in chain}
    return len(types)


def _chain_score(chain):
    """Composite: sum of edge suspicion, rewarded for crossing entity-type
    boundaries (real lateral movement) and for length, but not runaway --
    a single huge score shouldn't dominate over a coherent multi-step story."""
    base = sum(s for _, s in chain)
    diversity = _chain_type_diversity(chain)
    length_bonus = min(len(chain), MAX_CHAIN_LEN) * 0.3
    return round(base * (1 + 0.25 * (diversity - 1)) + length_bonus, 3)


def reconstruct_chains(events, top_k=8):
    scored_events = score_all(events, entity_type)
    successors, by_id = build_successor_index(scored_events)

    # seeds: any event above the noise floor can start a chain
    seeds = [(e, s) for e, s in scored_events if s >= MIN_EDGE_SCORE]

    all_chains = []
    for seed_e, seed_s in seeds:
        # beam search extending this seed
        beams = [[(seed_e, seed_s)]]
        completed = []
        for _ in range(MAX_CHAIN_LEN - 1):
            new_beams = []
            for chain in beams:
                last_e, _ = chain[-1]
                extended = False
                for nxt_e, nxt_s in sorted(successors.get(last_e.id, []), key=lambda p: -p[1])[:5]:
                    if any(nxt_e.id == e.id for e, _ in chain):
                        continue  # no repeats
                    new_beams.append(chain + [(nxt_e, nxt_s)])
                    extended = True
                if not extended:
                    completed.append(chain)
            if not new_beams:
                break
            new_beams.sort(key=_chain_score, reverse=True)
            beams = new_beams[:BEAM_WIDTH]
        completed.extend(beams)

        for c in completed:
            if len(c) >= 2 and _chain_score(c) >= MIN_CHAIN_SCORE:
                all_chains.append(c)

    # dedupe: keep the best-scoring chain per distinct "story" -- chains that
    # substantially overlap in (actor, target, event_type) triples are the
    # same underlying narrative found via slightly different connective
    # events, and only the best-scoring version is worth showing a judge.
    def _fingerprint(c):
        return frozenset((e.actor, e.target, e.event_type) for e, _ in c)

    all_chains.sort(key=_chain_score, reverse=True)
    kept = []
    seen_fps = []
    for c in all_chains:
        fp = _fingerprint(c)
        if any(len(fp & s) / max(1, min(len(fp), len(s))) >= 0.6 for s in seen_fps):
            continue
        seen_fps.append(fp)
        kept.append(c)
        if len(kept) >= top_k:
            break

    return kept, scored_events


def chain_to_dict(chain):
    return {
        "score": _chain_score(chain),
        "length": len(chain),
        "steps": [
            {
                "event_id": e.id,
                "ts": e.ts,
                "event_type": e.event_type,
                "actor": e.actor,
                "actor_type": entity_type(e.actor),
                "target": e.target,
                "target_type": entity_type(e.target),
                "detail": e.detail,
                "suspicion": s,
                "ground_truth_label": e.label,  # demo-only; not used by detection logic
            }
            for e, s in chain
        ],
    }
