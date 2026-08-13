# Azure Security Detection Lab — "Security Monkey"

A hands-on **Azure** security lab that deliberately injects **controlled misconfigurations** into
a throwaway cloud environment, then measures whether native controls (Microsoft Defender for
Cloud + Azure Policy) and an open-source CNAPP (Prowler) **detect and remediate** them. Inspired
by Netflix's Chaos Monkey, applied to **cloud security posture**.

> **Methodology:** *inject fault → observe detection → measure coverage gaps.* The headline
> deliverable is a **detection-coverage matrix**:
> `misconfig × {Defender for Cloud, Azure Policy, Prowler} → detected / missed / MTTD / MTTR`.

⚠️ **All misconfigurations here are intentional and self-inflicted in an isolated lab** for
detection testing — never attacks on third parties. Resources are scoped by tag/resource-group/
prefix and are torn down after every session.

---

## Architecture

```
                   ┌───────────────────────────────┐
                   │      Security Monkey (Py)      │
                   │  picks a misconfiguration,     │
                   │  applies it, supports revert   │
                   └───────────────┬───────────────┘
                                   │ azure_injectors
                                   ▼
                   ┌───────────────────────────────┐
                   │        Azure lab  (Terraform)  │
                   │  Resource Group · VNet/NSG ·   │
                   │  Storage account · RBAC        │
                   └───────────────┬───────────────┘
                                   │ detection
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                         ▼
 ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
 │  Defender for    │    │   Azure Policy   │    │  Prowler (CNAPP, │
 │  Cloud  (CSPM)   │    │ (+ remediation)  │    │  open source)    │
 └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
          └────────────────────────┼────────────────────────┘
                                   ▼
                    results/detection-coverage-matrix
```

---

## Repo structure

```
azure-security-lab/
├── README.md
├── terraform/
│   └── azure/                # lab RG, VNet/NSG, storage account, RBAC scope
├── security_monkey/          # Python package
│   ├── azure_injectors.py    # misconfig injectors + reverts
│   ├── base.py               # injector base class + injection ledger
│   ├── config.py             # env-driven config + safety guards
│   ├── monkey.py             # picks + applies a random misconfig
│   └── teardown.py           # revert everything the monkey touched
├── detection/                # Prowler run scripts, Azure Policy defs, notes
├── results/                  # findings exports + the detection-coverage matrix
└── docs/                     # architecture notes, findings write-up
```

---

## Misconfiguration scenarios

| Class | Injected misconfiguration |
|---|---|
| Network exposure | NSG inbound rule open to `0.0.0.0/0` (SSH/RDP) |
| Over-permissive identity | Broad RBAC role assignment at resource-group scope |
| Public data | Storage account + container opened to anonymous read |
| *(stretch)* Logging disabled | Disable a diagnostic setting |

---

## Prerequisites

- **Terraform** ≥ 1.6
- **Python** ≥ 3.10
- **Azure CLI** (`az login`) with a personal/lab subscription
- *(detection)* **Prowler** ≥ 4.x

## Quick start

```bash
# 0. Auth
az login
az account set --subscription "<your-lab-subscription-id>"

# 1. Set budget alerts FIRST (see Cost discipline below)

# 2. Deploy the lab (review the plan before applying!)
cd terraform/azure
cp example.tfvars terraform.tfvars   # edit values
terraform init
terraform plan
terraform apply

# 3. Install the Security Monkey
cd ../..
python -m venv .venv && source .venv/bin/activate
pip install -r security_monkey/requirements.txt

# 4. See what it would do WITHOUT touching anything
python -m security_monkey.monkey --dry-run

# 5. Inject a random misconfiguration (asks for confirmation)
python -m security_monkey.monkey

# 6. Run detection (Prowler + check Defender / Policy) ... fill the matrix

# 7. Revert everything the monkey did
python -m security_monkey.teardown

# 8. Tear down the lab entirely
cd terraform/azure && terraform destroy
```

Every injector run writes a record to `results/injections.log.json` so teardown knows exactly
what to revert.

---

## Cost discipline (real money — read this)

- **Set budget alerts** in Azure Cost Management *before* creating resources.
- Free-tier / B-series / smallest SKUs only. **No AKS/Kubernetes.**
- Everything is tagged `project=security-lab`; run **`terraform destroy`** after every session.
- Prefer Defender for Cloud **free CSPM tier**; enable paid plans only briefly if needed.
- Never leave public-exposure misconfigs running longer than a test cycle.

---

## Status

Azure scaffolding in place: Terraform lab module + Python Security Monkey injectors + teardown.
Next: deploy the lab, run the injectors, and populate the detection-coverage matrix in
[`results/`](results/).

## License

MIT — this is a personal portfolio / learning artifact by Bijan Fadaeinia.
