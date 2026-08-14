# Findings — Azure Security Detection Lab

A write-up of what this lab measured: whether native Azure controls (Microsoft Defender for Cloud,
Azure Policy) and an open-source CNAPP (Prowler) **detect and remediate** deliberately injected
misconfigurations — and where they don't.

> Scope: a single Azure subscription, `westeurope`, all resources tagged `project=security-lab`,
> no VMs (cost/safety). Tools: Prowler **v5.37.1**; Defender for Cloud **Foundational CSPM (free,
> enabled)**; Azure Policy built-ins. Results are from one measurement run and are reported with
> their caveats. Raw matrix: [`../results/detection-coverage-matrix.md`](../results/detection-coverage-matrix.md).

---

## 1. Problem

Most cloud breaches don't start with a novel exploit — they start with a **misconfiguration**: a
firewall open to the internet, a storage container left public, an identity granted far more than
it needs. These are *latent* weaknesses, not attacks, and in real environments they appear
constantly. The useful question is therefore not "can something be misconfigured" (trivially yes)
but **"if a misconfiguration appears, which of my controls notice, how fast, and does anything fix
it automatically?"**

## 2. Method

Borrowed from fault-injection testing: **inject → observe → measure**, against a known-good
baseline.

1. **Baseline** — Terraform builds a deliberately *secure* lab (locked-down NSG, storage with
   public access off, a private container, an unprivileged identity). Every experiment therefore
   has an unambiguous ground truth.
2. **Inject** — a Python "Security Monkey" weakens exactly one thing and records what it did to a
   JSON ledger.
3. **Observe** — run each detection control against the live misconfiguration.
4. **Measure** — record detected/missed, time-to-detect (MTTD), and whether it was
   auto-remediated (MTTR) into a coverage matrix.
5. **Revert** — the ledger drives a clean teardown; the lab is destroyed after each session.

## 3. Design

- **Lab (Terraform, `terraform/azure/`):** resource group, VNet/subnet, an NSG (deny-all inbound
  baseline), a StorageV2 account (`allowBlobPublicAccess = false`) + private container, and a
  throwaway user-assigned managed identity used as an RBAC target.
- **Security Monkey (`security_monkey/`):** an `Injector` base class with `inject()`/`revert()`,
  a subscription/RG/prefix **safety guard** that refuses to touch anything outside the lab, and a
  JSON **ledger** so teardown is reliable across sessions. Injectors:
  - `azure-nsg-open` — inbound `0.0.0.0/0` → TCP 22 & 3389 via `destination_port_ranges` (plural).
  - `azure-nsg-open-singleport` — same exposure to 3389 via `destination_port_range` (singular).
  - `azure-storage-public` — enable `allowBlobPublicAccess`, open the container to anonymous read.
  - `azure-rbac-broad` — assign **Owner** on the resource group to the throwaway identity.
- **Detection stack:** Prowler (on-demand, uses the CLI session), Defender for Cloud (periodic
  CSPM), Azure Policy (a built-in **Modify** policy that both flags and remediates).

## 4. Results

Legend: ✅ detected · ⚠️ partial · ❌ missed · 🔧 auto-remediated · — not applicable/tested

| Misconfiguration | Defender for Cloud | Azure Policy | Prowler |
|---|---|---|---|
| Network exposure (`azure-nsg-open`) | — not tested (VM-centric; no VM) | — | ⚠️ **misses multi-port rule** |
| Public data (`azure-storage-public`) | ❌ not observed (see F4) | ✅ detect → 🔧 **auto-remediate** | ✅ detected (seconds) |
| Over-permissive identity (`azure-rbac-broad`) | — owner-count oriented | — thin coverage | ❌ **missed** |

### F1 — Prowler misses multi-port NSG rules (network exposure)
Prowler reported the NSG as **compliant** for RDP/SSH internet access even though an inbound rule
allowed `0.0.0.0/0` to TCP 22 & 3389. Root cause, confirmed in the check source
(`network_rdp_internet_access_restricted.py`): the checks evaluate only
`rule.destination_port_range` (**singular**) and ignore `destination_port_ranges` (**plural**).
A controlled A/B test made this unambiguous:

| NSG rule form | RDP check result |
|---|---|
| 3389 via `destination_port_ranges` (plural) | **PASS** — missed |
| 3389 via `destination_port_range` (singular) | **FAIL** — caught |

Same resource, same real exposure; detection flipped purely on the port-field representation.
Multi-port rules using `destination_port_ranges` are common in real Azure NSGs, so this is a
genuine coverage gap — a candidate upstream fix/PR to Prowler.

### F2 — Prowler detects public storage instantly
`azure-storage-public` was flagged in seconds by `storage_blob_public_access_level_is_disabled`.
Attribution matters: the storage scan returned 14 fails, but 13 were pre-existing baseline
hardening gaps (soft-delete, geo-redundancy, CMK, private endpoints, etc.); **only** the public-
access check was attributable to the injection (PASS at baseline → FAIL after).

### F3 — Azure Policy detects *and* auto-remediates public storage
A built-in **Modify** policy ("Configure your Storage account public access to be disallowed"),
assigned at the RG with a managed identity granted *Storage Account Contributor*, flagged the
account **NonCompliant** and — via a remediation task — set `allowBlobPublicAccess = false`
automatically, with no manual resource edit. Because the Modify effect stays assigned, it also
**prevents** re-enabling public access on future writes. This is the strongest single result: a
full **detect → auto-remediate (and prevent)** loop, reproducible as code
([`../detection/azure-policy/`](../detection/azure-policy/)).

### F4 — Defender for Cloud: not observed (timing, not absence)
Foundational CSPM was enabled, so Defender *was* assessing — yet no recommendation appeared during
the session. The public-storage exposure window was only ~33 minutes (injected → Policy
auto-remediated), while Defender's CSPM cadence is hours. **Fast automated remediation outpaced
slow native detection.** (The network case wasn't tested against Defender: its NSG recommendations
are VM-centric and the lab runs no VM.) A hard Defender MTTD would need a dedicated run with
remediation disabled and a multi-hour wait.

### F5 — Over-permissive RBAC is not detected (identity)
`azure-rbac-broad` granted **Owner** on the resource group to a workload (managed) identity. A
Prowler `iam`+`entra` scan returned many fails, but **none referenced the injected assignment**
(verified by grepping the output for the principal ID and resource scope — zero matches). Prowler's
Azure IAM checks target custom-role *definitions*, User Access Administrator, and subscription-level
owner hygiene — not RG-scoped role assignments to workload identities. Defender's RBAC
recommendations are similarly oriented at subscription-level *human* owner counts. The class is
broadly under-covered.

## 5. Takeaways

1. **Coverage is uneven by domain.** Strong for storage/data config, a real blind spot for network
   nuance, weak for identity/RBAC. Posture tooling reads *resource configuration* well but
   struggles with **RBAC intent and blast-radius**.
2. **Open-source vs native is complementary, not ranked.** Prowler was instant and portable but had
   a real blind spot (F1); Azure Policy was the only tool that *fixed* anything (F3); Defender's
   value is continuous assessment, but its latency means fast remediation can close a gap before it
   reports (F4).
3. **Automated remediation changes the game** — and can mask slow detectors. Worth measuring both.
4. **Read the checks, don't just run them.** F1 was only provable by reading Prowler's source; a
   green result is not the same as "safe."

## 6. Limitations

Single run; on-demand scans were forced (real unattended cadences are slower); no VMs (so some
Defender network recommendations are out of scope by design); the public container held no data;
findings are specific to the tool versions noted above.

## 7. Reproduce

See the repository [`README.md`](../README.md) (quick start), the injectors in
[`../security_monkey/`](../security_monkey/), and the Policy-as-code in
[`../detection/azure-policy/`](../detection/azure-policy/). The live coverage matrix is in
[`../results/detection-coverage-matrix.md`](../results/detection-coverage-matrix.md).
