# Detection-Coverage Matrix

The headline deliverable. For each injected misconfiguration, record whether each control
detected it, how long it took (MTTD), and whether it was auto-remediated (MTTR).

Legend: ✅ detected · ❌ missed · ⏳ MTTD · 🔧 auto-remediated (MTTR) · — n/a

| Misconfig class | Injector | Defender for Cloud | Azure Policy | Prowler |
|---|---|---|---|---|
| Network exposure | `azure-nsg-open` | _tbd_ | _tbd_ | ⚠️ **partial** — misses multi-port; see note 1 |
| Public data | `azure-storage-public` | _tbd (Defender clock started 2026-08-14 08:24)_ | _tbd_ | ✅ detected (instant) — see note 2 |
| Over-permissive identity | `azure-rbac-broad` | _tbd_ | _tbd_ | _tbd_ |

## Notes / observations

**Note 1 — Prowler blind spot: multi-port NSG rules (network exposure).**
Prowler **v5.37.1**'s Azure network internet-access checks evaluate only
`rule.destination_port_range` (singular) and ignore `destination_port_ranges` (plural). Verified
in the check source (`network_rdp_internet_access_restricted.py`) and confirmed by a controlled
A/B experiment on `seclab-nsg` (2026-08-13):

| NSG state | RDP check (`network_rdp_internet_access_restricted`) |
|---|---|
| Rule opens 3389 via `destination_port_ranges` (plural) — `azure-nsg-open` | **PASS** (missed) |
| + rule opens 3389 via `destination_port_range` (singular) — `azure-nsg-open-singleport` | **FAIL** (caught) |

Same resource, same real internet exposure (`0.0.0.0/0` → 3389); detection flips purely on the
port-field representation. `network_ssh_internet_access_restricted` also stayed **PASS** while
port 22 was genuinely open via the plural rule — a second instance of the same gap. Source-address
handling (`0.0.0.0/0`) is correct. Multi-port rules using `destination_port_ranges` are common in
real Azure NSGs, so this is a genuine coverage gap → candidate upstream fix/PR to Prowler.

**Note 2 — Prowler detects the public-data injection (instant).**
`azure-storage-public` set account `allowBlobPublicAccess` → true and opened container `labdata`
to anonymous read (injected 2026-08-14 08:24). Prowler's on-demand storage scan (08:26) flagged
it via **`storage_blob_public_access_level_is_disabled`** (High) — MTTD ≈ scan time (seconds).
Attribution: the scan showed 14 storage FAILs, but 13 are pre-existing *baseline hardening* gaps on
a minimal account (soft-delete, geo-redundancy, CMK, private endpoints, infra encryption, key
rotation, cross-tenant replication, and the shared-key / public-network-access defaults from the
Terraform baseline). **Only `storage_blob_public_access_level_is_disabled` is attributable to the
injection** (PASS at baseline → FAIL after). Contrast with note 1: Prowler caught the public
storage instantly but missed the multi-port NSG exposure.
