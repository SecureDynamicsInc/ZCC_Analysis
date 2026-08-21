# SOP: Possible direct-P2P app blocked by ZIA

This document covers the pattern where a SaaS app surfaces as
"connection failed" but the actual breakage isn't visible in the
SaaS's control channel — because the app uses a direct peer-to-peer
data plane that ZIA is blocking. Detected by
`zcc_diag/issues/p2p_app_blocked.py`.

The user thinks "Zscaler broke this SaaS." ZCC's tunnel state looks
healthy. The detector surfaces a burst of outbound UDP/TCP failures
to public-internet IPs on non-standard ports — which fits the shape
of a P2P data plane, not server-bound traffic.

Detection grounded in an anonymized internal case (Example Tenant J
JumpCloud Remote Assist on macOS, closed `ISSUE_FIXED`). observed
from the 2026-02-06 Zoom AI Summary:

> *"Patrick discovered that remote assistance connections were
> failing because ZIA needed to be disabled on both devices
> involved in the connection. He realized that the remote
> assistance was not connecting to JumpCloud servers but rather
> establishing a direct connection between the devices, which was
> being blocked by ZIA."*

> **This is a WARNING-level heuristic.** The detector can't confirm
> a P2P attempt happened — the application's own logs aren't in the
> ZCC bundle. The SOP guides the operator to confirm with the user
> before acting.

---

## Possible direct-P2P app blocked by ZIA
<a id="possible-p2p-app-blocked"></a>

**Detected when:** three or more distinct outbound connection
failures fire against public-internet IPs (not RFC1918, not Zscaler
CGNAT, not multicast) on non-standard ports (not 80/443/53/22/etc),
while no `FIREWALL_BLOCK_ERROR`, `SERVER_DOWN_ERROR`, or
`LOCAL_PROXY_FORWARDING` transitions appeared in the same bundle.

**What it means:** the tunnel itself is fine. The failures are
to peer destinations that look like real public-internet peers,
not infrastructure. The most common cause is that a user-action
P2P attempt (Zoom screen share, JumpCloud Remote Assist, etc.)
hit ZIA's per-flow inspection and was blocked.

**Triage steps:**

### Step 1: Identify the app

Ask the user: *"What app were you using when this happened?"*

Compare against the known-P2P catalogue:

- **JumpCloud Remote Assist** — verified P2P, the Example Tenant J case
- **Zoom screen share** (peer-to-peer mode, when enabled in Zoom
  admin settings)
- **Microsoft Teams calls** (DirectConnect / Teams Direct Routing,
  some configurations)
- **BlueJeans Network** (legacy meetings)
- **Discord voice channels**
- **TeamViewer direct-connect mode** (vs the relayed default)
- **Apple Continuity / Universal Control** (Mac-to-Mac handoff)
- **Steam Remote Play** (game streaming between user devices)
- **Google Meet** (rare; only when P2P mode is forced)
- **Skype legacy** (pre-cloud / on-prem)

If the user names something not on the list, ask whether the
flow is device-to-device or device-to-server. The presence of
"share screen with another user" / "remote control another user's
device" / "voice call directly to a peer" is the tell.

### Step 2: Confirm via the elimination test

The Example Tenant J transcript captured the canonical diagnostic:

> *"Disable ZIA on **both** endpoints (sender and receiver) and
> retry. If the action works with ZIA disabled on both, the root
> cause is ZIA blocking the P2P leg."*

This is also a useful sanity check — if disabling ZIA on one
endpoint isn't enough, the failure is bi-directional, which
strongly suggests P2P.

### Step 3: Fix

Two options:

**A. App-profile bypass (preferred, narrowly scoped):**
- For known-P2P apps with documented port ranges, add the app's
  UDP/TCP range to the customer's app-profile bypass.
- Examples: Zoom client publishes its IP/port ranges; Microsoft
  Teams publishes Office 365 endpoint URLs.

**B. Disable ZIA on affected user(s) (operational fallback):**
- If the app's port ranges aren't documented or are too broad,
  scope ZIA off for the specific users / groups affected.
- Less ideal because it leaves those users without ZIA-side
  protection.

### Step 4: Verify

Have the user retry the failing action with policy in place.
Confirm the P2P leg now establishes (the app should show "connected
peer-to-peer" or equivalent UI indicator).

---

## Why this is WARNING severity (not CRITICAL)

The detector can't confirm a P2P attempt happened from ZCC's logs
alone — the application is the ground truth. False positives here
are common (any app making outbound connections to random public
peers on non-standard ports triggers the pattern). The SOP exists
to walk the operator through confirming before acting.

Once you've validated this pattern against a real case, consider
adding an app-specific detector (similar to `ai_cli_pin` or
`rmm_agent_pin`) for the specific vendor — those fire at higher
confidence because they're keyed on known endpoints.
