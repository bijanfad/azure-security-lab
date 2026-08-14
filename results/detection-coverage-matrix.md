# Detection-Coverage Matrix

The headline deliverable. For each injected misconfiguration, record whether each control
detected it, how long it took (MTTD), and whether it was auto-remediated (MTTR).

Legend: ✅ detected · ❌ missed · ⏳ MTTD · 🔧 auto-remediated (MTTR) · — n/a

**Key takeaways (Azure, this run).** Coverage is strongest for *storage/data* config, weaker for
*network* nuance, and weakest for *identity/RBAC*:
- **Public data** — best covered: Prowler flagged it in seconds; Azure Policy detected **and
  auto-remediated** it; only Defender missed it, purely because fast remediation closed the
  exposure window before its slow CSPM cycle ran (note 4).
- **Network exposure** — Prowler has a real **blind spot**: it misses multi-port NSG rules
  (`destination_port_ranges`), catching only the singular form (note 1).
- **Over-permissive identity** — **broadly uncovered**: Prowler doesn't flag RG-scoped role
  assignments to workload identities; native RBAC controls target subscription-level human owners
  (note 5). CSPM reads config well but struggles with RBAC intent/blast-radius.

| Misconfig class | Injector | Defender for Cloud | Azure Policy | Prowler |
|---|---|---|---|---|
| Network exposure | `azure-nsg-open` | — not tested (note 4) | _tbd_ | ⚠️ **partial** — misses multi-port; see note 1 |
| Public data | `azure-storage-public` | ❌ not observed — note 4 | ✅ detected → 🔧 auto-remediated — note 3 | ✅ detected (instant) — note 2 |
| Over-permissive identity | `azure-rbac-broad` | — not tested (owner-count oriented; note 5) | _tbd (thin built-in coverage)_ | ❌ missed — note 5 |

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

**Note 3 — Azure Policy: detect *and* auto-remediate the public-data injection.**
Assigned the built-in **Modify** policy "Configure your Storage account public access to be
disallowed" (`13502221-8df0-4414-9937-de9c5c4e396b`) at the lab RG with a system-assigned managed
identity (granted **Storage Account Contributor**). Timeline (2026-08-14): injected **08:24** →
`az policy state trigger-scan` reported the account **NonCompliant** ~**08:45** → remediation task
(`ExistingNonCompliant`) created **08:56:55**, `provisioningState: Succeeded`, and
`allowBlobPublicAccess` verified **false** within ~1–2 min. So Policy provided **detection + the
one automated remediation** (deliverable #4). Honest caveats: unattended Policy evaluation runs on
a cycle up to ~24h (we forced it on-demand — so realistic MTTD is "next cycle," not seconds); and
remediating *existing* resources requires a remediation task. Bonus: because the Modify effect is
still assigned, it now also **prevents** re-enabling public access (it intercepts the ARM write) —
a prevention story on top of remediation. Reproducible commands: `detection/azure-policy/`.

**Note 4 — Defender for Cloud: not observed this run (timing, not absence).**
`FoundationalCspm` is **enabled (Standard)** on the subscription — verified via `az security
pricing list` — so Defender *is* assessing. Yet no recommendation for `seclab-rg` appeared during
the session, because Defender's CSPM assessment cadence is slow (hours) while the public-storage
exposure window was only ~33 min (injected 08:24 → Policy auto-remediated ~08:57). **Fast automated
remediation outpaced slow native CSPM detection** — an interesting interplay, not a Defender
failure. The network-exposure case wasn't tested against Defender: its NSG recommendations are
VM-centric and the lab runs no VM. To get a hard Defender MTTD, run a dedicated experiment —
inject `azure-storage-public`, do **not** assign the Modify remediation policy, leave it several
hours, then read Recommendations.

**Note 5 — Over-permissive RBAC is not detected by Prowler (verified).**
`azure-rbac-broad` granted **Owner** on the lab RG to a throwaway user-assigned managed identity
(`seclab-target-mi`, principal `5e58cf57…`). A Prowler `iam`+`entra` scan (2026-08-14) returned
102 fails, but **none reference the injected assignment** (verified by grepping the OCSF output for
the principal ID / `seclab-target-mi` / `resourceGroups/seclab-rg` — zero matches). Prowler's Azure
IAM checks target custom-role *definitions*, User Access Administrator assignments, and
subscription-level owner hygiene — not RG-scoped role assignments to workload identities. Defender
for Cloud's RBAC recommendations are likewise oriented at subscription-level *human* owner counts.
So the over-permissive-identity class is **broadly under-covered by CSPM** — posture tooling reads
resource config well but struggles with RBAC intent and blast-radius. (The 99 Entra fails are
tenant-wide identity hygiene unrelated to the injection.)
