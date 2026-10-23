"""Central tunables for the whole pipeline.

Every magic number the report quotes lives here so the values in the slides and
the values in the code can never drift apart.
"""

from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models"
DATA_DIR = ROOT / "data"
CAPTURE_DIR = ROOT / "captures"
MODEL_PATH = MODEL_DIR / "netlens_model.joblib"
DATASET_PATH = DATA_DIR / "netlens_flows.csv"

# ---------------------------------------------------------------- L1 capture
RING_BUFFER_SIZE = 20_000      # bounded deque, drop-oldest
DEFAULT_BPF = ""               # e.g. "tcp or udp or icmp"

# ---------------------------------------------------------------- L2 flows
FLOW_IDLE_TIMEOUT = 15.0       # s with no packets -> flow is closed
FLOW_ACTIVE_TIMEOUT = 120.0    # s max lifetime -> force eviction
MAX_LADDER_PACKETS = 60        # packets retained per flow for the session ladder
MAX_FLOW_TABLE = 20_000        # hard cap on concurrently tracked flows

# ---------------------------------------------------------------- L3 detection
RULE_WINDOW = 10.0             # sliding window for the deterministic detectors
PORTSCAN_MIN_PORTS = 15        # distinct dst ports from one src inside the window
PORTSCAN_MIN_HOSTS = 10        # distinct dst hosts on one port (horizontal scan)
SYNFLOOD_MIN_SYNS = 60         # SYNs inside the window
SYNFLOOD_RATIO = 3.0           # SYN : SYN-ACK ratio that counts as half-open
ICMPFLOOD_MIN_PKTS = 80
DNS_ENTROPY_THRESHOLD = 3.6    # bits/char -> encoded payload, not a hostname
DNS_MIN_QNAME_LEN = 40
BRUTE_MIN_ATTEMPTS = 12        # short sessions to one auth port inside the window

BASELINE_SECONDS = 60.0        # N1: Isolation Forest self-baseline duration
BASELINE_MIN_FLOWS = 40        # ... but never fit on fewer flows than this
BASELINE_MAX_FLOWS = 600       # ... and fit early if a busy link reaches this
IFOREST_CONTAMINATION = 0.03
IFOREST_ALERT_SCORE = -0.05    # decision_function below this -> anomalous flow

SUPERVISED_MIN_CONFIDENCE = 0.70   # probability needed before raising a class alert

# A flow is only scored once it has "settled".  Settled means finished, not
# merely quiet: an interactive SSH session is idle between keystrokes, and
# judging it mid-pause makes it look exactly like a brute-force attempt
# (complete handshake, a few hundred bytes, short duration).  So a flow
# qualifies when it is TCP-terminated (FIN/FIN or RST), or has been idle
# longer than any human typing cadence, or already carries enough packets for
# its shape to be unambiguous.
FLOW_SETTLE_IDLE = 3.0
FLOW_SETTLE_PACKETS = 40

ALERT_COOLDOWN = 20.0          # s before the same (kind, source) alert repeats
MAX_ALERTS = 400

# ---------------------------------------------------------------- L5 dashboard
UI_REFRESH_SECONDS = 2.0
TIMELINE_WINDOW = 120          # s of history in the traffic timeline
TOP_N = 10

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
