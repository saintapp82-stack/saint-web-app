"""
SAINT — synthetic security event generator.

Produces a stream of events over N hours for M entities, with:
  - background "normal" traffic (logins, routine admin work)
  - legitimate but *unusual* admin activity (to test false-positive resistance)
  - one or more embedded attack chains (the thing we need to detect)

Event schema:
    {
        id: str
        ts: float (unix epoch seconds)
        event_type: str   # login | perm_change | file_download | process_exec | network_conn | account_create
        actor: str        # entity id performing the action
        target: str       # entity id acted upon (can equal actor for self actions)
        detail: dict      # free-form extra fields (ip, file, permission, etc.)
        label: str        # "background" | "admin_noise" | "attack" -- GROUND TRUTH, for demo/eval only.
                           # The detection code never reads this field.
    }
"""
import random
import time
import uuid
from dataclasses import dataclass, field, asdict


@dataclass
class Event:
    ts: float
    event_type: str
    actor: str
    target: str
    detail: dict = field(default_factory=dict)
    label: str = "background"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])

    def to_dict(self):
        return asdict(self)


ENTITY_TYPES = {
    "user": [f"user_{i}" for i in range(1, 13)],
    "machine": [f"host_{i:02d}" for i in range(1, 21)],
    "service": ["svc_auth", "svc_billing", "svc_hr", "svc_fileshare", "svc_admin_panel", "svc_backup"],
    "account": [f"acct_{i}" for i in range(1, 8)] + ["acct_domain_admin", "acct_svc_deploy"],
}

ALL_ENTITIES = [e for group in ENTITY_TYPES.values() for e in group]


def entity_type(e):
    for t, members in ENTITY_TYPES.items():
        if e in members:
            return t
    return "unknown"


def _rand_ts(start, hours):
    return start + random.uniform(0, hours * 3600)


def _business_hour_ts(day_start, day_offset=0):
    # business hours 8am-7pm, biased toward 9-5
    h = random.triangular(8, 19, 13)
    return day_start + day_offset * 86400 + h * 3600


def generate_background(n_events, start_ts, hours):
    """Normal, boring traffic: users logging into their usual machines during business hours."""
    events = []
    user_home_machine = {u: random.choice(ENTITY_TYPES["machine"]) for u in ENTITY_TYPES["user"]}
    for _ in range(n_events):
        u = random.choice(ENTITY_TYPES["user"])
        m = user_home_machine[u]
        ts = _business_hour_ts(start_ts, random.randint(0, max(0, int(hours // 24))))
        events.append(Event(
            ts=ts, event_type="login", actor=u, target=m,
            detail={"ip": f"10.0.{random.randint(0,5)}.{random.randint(2,254)}", "result": "success"},
            label="background",
        ))
        if random.random() < 0.3:
            events.append(Event(
                ts=ts + random.uniform(60, 1800), event_type="file_download", actor=u, target=m,
                detail={"file": random.choice(["report.xlsx", "notes.docx", "slides.pptx"]), "size_mb": random.randint(1, 20)},
                label="background",
            ))
    return events


def generate_admin_noise(n_events, start_ts, hours):
    """Legitimate but *unusual-looking* admin activity — the false-positive trap.
    Real admins doing real permission changes and off-hours maintenance."""
    admins = ["user_1", "user_2"]  # designated sysadmins
    events = []
    for _ in range(n_events):
        a = random.choice(admins)
        target_acct = random.choice(ENTITY_TYPES["account"])
        ts = _rand_ts(start_ts, hours)  # can be any hour, including off-hours maintenance windows
        kind = random.choice(["perm_change", "account_create", "process_exec"])
        if kind == "perm_change":
            events.append(Event(
                ts=ts, event_type="perm_change", actor=a, target=target_acct,
                detail={"change": random.choice(["grant_read", "revoke_write", "rotate_key"]), "ticket": f"OPS-{random.randint(1000,9999)}"},
                label="admin_noise",
            ))
        elif kind == "account_create":
            events.append(Event(
                ts=ts, event_type="account_create", actor=a, target=f"acct_tmp_{uuid.uuid4().hex[:4]}",
                detail={"ticket": f"OPS-{random.randint(1000,9999)}"},
                label="admin_noise",
            ))
        else:
            events.append(Event(
                ts=ts, event_type="process_exec", actor=a, target=random.choice(ENTITY_TYPES["machine"]),
                detail={"proc": random.choice(["patch.sh", "backup.py", "healthcheck.exe"])},
                label="admin_noise",
            ))
    return events


def generate_attack_chain(start_ts, hours, chain_id="attack1"):
    """
    Embed ONE realistic multi-stage attack, spread across the window, using
    only actions that individually look plausible:

      1. Off-hours login from an unusual source IP (initial compromise / phished creds)
      2. Recon: unusual file_download of a credentials-adjacent file
      3. Lateral movement: login to a machine this user has never touched
      4. Privilege escalation: perm_change granting broader access
      5. Access to a sensitive service (admin panel / backup)
      6. Exfil-style large file_download from that service
    """
    non_admin_users = [u for u in ENTITY_TYPES["user"] if u not in ("user_1", "user_2")]
    victim = random.choice(non_admin_users)
    normal_machine = random.choice(ENTITY_TYPES["machine"])
    lateral_machine = random.choice([m for m in ENTITY_TYPES["machine"] if m != normal_machine])
    target_account = "acct_domain_admin"
    sensitive_service = random.choice(["svc_admin_panel", "svc_backup"])

    t0 = start_ts + hours * 3600 * 0.4  # start partway through the window
    events = [
        Event(ts=t0, event_type="login", actor=victim, target=normal_machine,
              detail={"ip": "203.0.113.77", "result": "success", "note": "unusual source IP, 3am"},
              label="attack"),
        Event(ts=t0 + 900, event_type="file_download", actor=victim, target=normal_machine,
              detail={"file": "saved_passwords.csv", "size_mb": 1}, label="attack"),
        Event(ts=t0 + 3600, event_type="login", actor=victim, target=lateral_machine,
              detail={"ip": "203.0.113.77", "result": "success", "note": "never accessed before"},
              label="attack"),
        Event(ts=t0 + 4500, event_type="perm_change", actor=victim, target=target_account,
              detail={"change": "grant_admin", "ticket": None}, label="attack"),
        Event(ts=t0 + 5400, event_type="login", actor=target_account, target=sensitive_service,
              detail={"ip": "203.0.113.77", "result": "success"}, label="attack"),
        Event(ts=t0 + 6000, event_type="file_download", actor=target_account, target=sensitive_service,
              detail={"file": "customer_db_backup.tar.gz", "size_mb": 4200}, label="attack"),
    ]
    for e in events:
        e.detail["chain_id"] = chain_id
    return events


def generate_dataset(hours=48, n_background=600, n_admin_noise=40, n_attacks=1, seed=42):
    random.seed(seed)
    start_ts = time.time() - hours * 3600
    events = []
    events += generate_background(n_background, start_ts, hours)
    events += generate_admin_noise(n_admin_noise, start_ts, hours)
    for i in range(n_attacks):
        events += generate_attack_chain(start_ts, hours, chain_id=f"attack{i+1}")
    events.sort(key=lambda e: e.ts)
    return events


if __name__ == "__main__":
    ds = generate_dataset()
    print(f"generated {len(ds)} events")
    from collections import Counter
    print(Counter(e.label for e in ds))
