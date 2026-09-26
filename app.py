import os
import time
from flask import Flask, jsonify, send_from_directory, request

from events import generate_dataset, entity_type, ENTITY_TYPES
from chains import reconstruct_chains, chain_to_dict, build_entity_graph
from scoring import score_all

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=STATIC_DIR)

_cache = {}


def get_dataset(seed=42, n_attacks=1):
    key = (seed, n_attacks)
    if key not in _cache:
        events = generate_dataset(hours=48, n_background=600, n_admin_noise=40,
                                   n_attacks=n_attacks, seed=seed)
        chains, scored = reconstruct_chains(events, top_k=10)
        _cache[key] = {
            "events": events,
            "scored": scored,
            "chains": chains,
        }
    return _cache[key]


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/summary")
def summary():
    seed = int(request.args.get("seed", 42))
    n_attacks = int(request.args.get("attacks", 1))
    d = get_dataset(seed, n_attacks)
    scored = d["scored"]
    return jsonify({
        "total_events": len(d["events"]),
        "flagged_events": sum(1 for _, s in scored if s >= 0.6),
        "chains_found": len(d["chains"]),
        "entity_counts": {t: len(v) for t, v in ENTITY_TYPES.items()},
    })


@app.route("/api/chains")
def chains_endpoint():
    seed = int(request.args.get("seed", 42))
    n_attacks = int(request.args.get("attacks", 1))
    d = get_dataset(seed, n_attacks)
    return jsonify([chain_to_dict(c) for c in d["chains"]])


@app.route("/api/graph")
def graph_endpoint():
    """Full entity graph (for the background visualization), lightly summarized."""
    seed = int(request.args.get("seed", 42))
    n_attacks = int(request.args.get("attacks", 1))
    d = get_dataset(seed, n_attacks)
    G = build_entity_graph(d["scored"])
    nodes = [{"id": n, "type": G.nodes[n].get("type", "unknown")} for n in G.nodes]
    edges = []
    for u, v, data in G.edges(data=True):
        e = data["event"]
        edges.append({
            "source": u, "target": v, "score": data["score"],
            "event_type": e.event_type, "ts": e.ts,
        })
    return jsonify({"nodes": nodes, "edges": edges})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False)