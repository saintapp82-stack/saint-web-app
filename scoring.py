"""
Baseline modeling + anomaly scoring.

Core idea: an action is only suspicious *relative to that entity's own PRIOR
history* -- scoring is strictly causal. We walk events in time order and,
for each one, score it against the baseline built from everything before it,
THEN fold it into the baseline. (Building the whole-history baseline first
and scoring against it would leak future events into "what's normal", which
silently erases the very anomalies we're trying to catch.)

A sysadmin doing perm_changes at 3am is normal for that sysadmin by the time
we've seen a few of them. A random user doing it once, from a source IP
they've never used, is not. This asymmetry is what keeps legitimate admin
work from flooding the output with alerts.
"""
import math
from collections import defaultdict

ACTION_RISK = {
    "login": 1.0,
    "file_download": 1.3,
    "perm_change": 2.2,
    "account_create": 2.0,
    "process_exec": 1.4,
    "network_conn": 1.1,
}

# Hops between these entity-type pairs cross a trust boundary and are
# inherently more sensitive than same-type or expected pairs.
BOUNDARY_RISK = {
    ("user", "account"): 1.6,
    ("account", "service"): 1.5,
    ("user", "service"): 1.3,
}


class EntityBaseline:
    """Learned 'normal' behavior for one entity, updated incrementally."""
    def __init__(self):
        self.seen_targets = set()
        self.seen_ips = set()
        self.hour_counts = defaultdict(int)
        self.total_events = 0
        self.max_file_mb = 0

    def observe(self, hour, target, ip=None, size_mb=0):
        self.hour_counts[hour] += 1
        self.seen_targets.add(target)
        if ip:
            self.seen_ips.add(ip)
        self.total_events += 1
        self.max_file_mb = max(self.max_file_mb, size_mb)

    def hour_rarity(self, hour):
        if self.total_events < 5:
            return 0.3  # not enough history to judge yet -- mild default
        p = self.hour_counts.get(hour, 0) / self.total_events
        return 1.0 - min(1.0, p * 24)

    def target_novelty(self, target):
        if self.total_events == 0:
            return 0.3  # first-ever action for this actor: mildly notable, not alarming
        return 0.0 if target in self.seen_targets else 1.0

    def ip_novelty(self, ip):
        if not ip:
            return 0.0
        if self.total_events == 0:
            return 0.2
        return 0.0 if ip in self.seen_ips else 1.0

    def size_novelty(self, size_mb):
        if size_mb <= 0 or self.max_file_mb == 0:
            return 0.0
        ratio = size_mb / max(self.max_file_mb, 1)
        return min(1.0, math.log1p(ratio) / math.log1p(20))


def score_all(events, entity_type_fn):
    """
    Single causal pass: events are processed in time order. Each event is
    scored against its actor's baseline-so-far, then the baseline is updated.
    Returns list of (event, score) in the SAME order as input `events`.
    """
    order = sorted(range(len(events)), key=lambda i: events[i].ts)
    baselines = defaultdict(EntityBaseline)
    scores = [None] * len(events)

    for i in order:
        e = events[i]
        b = baselines[e.actor]
        hour = int((e.ts // 3600) % 24)
        detail = e.detail if isinstance(e.detail, dict) else {}
        size_mb = detail.get("size_mb", 0)
        ip = detail.get("ip")

        hour_r = b.hour_rarity(hour)
        # account_create's target is, by definition, a brand-new resource --
        # "have I seen this target before" is meaningless signal here, so we
        # don't let it inflate the score the way it would for e.g. a login.
        target_r = 0.0 if e.event_type == "account_create" else b.target_novelty(e.target)
        ip_r = b.ip_novelty(ip)
        size_r = b.size_novelty(size_mb)

        behavioral = 0.35 * hour_r + 0.8 * target_r + 0.9 * ip_r + 0.5 * size_r

        action_w = ACTION_RISK.get(e.event_type, 1.0)
        at, tt = entity_type_fn(e.actor), entity_type_fn(e.target)
        boundary_w = BOUNDARY_RISK.get((at, tt), 1.0)

        ticket_bonus = 0.0
        if e.event_type == "perm_change" and not detail.get("ticket"):
            ticket_bonus = 1.2

        score = (behavioral + ticket_bonus) * action_w * boundary_w
        scores[i] = round(score, 3)

        b.observe(hour, e.target, ip=ip, size_mb=size_mb)

    return list(zip(events, scores))
