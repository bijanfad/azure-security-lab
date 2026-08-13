# Azure Security Detection Lab — "Security Monkey"

A hands-on **Azure** security lab that deliberately injects **controlled misconfigurations** into
a throwaway cloud environment, then measures whether native controls (Microsoft Defender for
Cloud + Azure Policy) and an open-source CNAPP (Prowler) **detect and remediate** them. Inspired
by Netflix's Chaos Monkey, applied to **cloud security posture**.

> **Methodology:** *inject fault → observe detection → measure coverage gaps.* The headline
> deliverable is a **detection-coverage matrix**:
> `misconfig × {Defender for Cloud, Azure Policy, Prowler} → detected / missed / MTTD / MTTR`.

> **Scope:** Azure is the complete project. It is built **multi-cloud-ready** — an **AWS mirror**
> is an optional future extension, not part of the core deliverable.

⚠️ **All misconfigurations here are intentional and self-inflicted in an isolated lab** for
detection testing — never attacks on third parties. Resources are scoped by tag/resource-group/
prefix and are torn down after every session.

---

## Architecture

```
                       ┌──────────────────────────────┐
                       │      Security Monkey (Py)     │
                       │  picks 1 random misconfig,    │
                       │  applies it, supports revert  │
                       └───────────────┬──────────────┘
                        azure_injectors │ aws_injectors
                ┌───────────────────────┴───────────────────────┐
                ▼                                                 ▼
        ┌───────────────┐                                 ┌───────────────┐
        │     AZURE     │                                 │      AWS      │
        │ lab RG (TF)   │                                 │  lab (TF)     │
        │ NSG / Storage │                                 │ SG / S3 / IAM │
        │ RBAC          │                                 │               │
        └───────┬───────┘                                 └───────┬───────┘
                │ detection                                       │ detection
     ┌──────────┴──────────┐                          ┌───────────┴──────────┐
     ▼                     ▼                          ▼                      ▼
 Defender for Cloud    Azure Policy               Security Hub          AWS Config
 (CSPM)                (+ remediation)            
     └──────────┬──────────┘                          └───────────┬──────────┘
                └───────────────────┬───────────────────────────┘
                                    ▼
                          ┌───────────────────┐
                          │  Prowler (CNAPP)  │  runs natively on both clouds
                          └─────────┬─────────┘
                                    ▼
                       results/detection-coverage-matrix
```

*The diagram shows the full multi-cloud-ready design. **This project implements the Azure
branch**; the AWS branch is an optional future extension.*

---

## Repo structure

```
azure-security-lab/
├── CLAUDE.md                 # project context / instructions
├── README.md
├── terraform/
│   ├── azure/                # lab RG, VNet/NSG, storage, RBAC test principal
│   └── aws/                  # VPC/SG, S3, IAM  (optional future extension)
├── security_monkey/          # Python package
│   ├── azure_injectors.py    # Azure misconfig injectors + reverts
│   ├── aws_injectors.py      # AWS injectors (future-extension stubs)
│   ├── config.py             # env-driven config + safety guards
│   ├── monkey.py             # picks + applies a random misconfig
│   └── teardown.py           # revert everything the monkey touched
├── detection/                # Prowler run scripts, Azure Policy defs, notes
├── results/                  # findings exports + the detection-coverage matrix
└── docs/                     # architecture diagram, write-up / blog draft
```

---

## Misconfiguration scenarios

| Class | Azure (this project) | AWS *(optional future extension)* |
|---|---|---|
| Network exposure | NSG rule open to `0.0.0.0/0` | Security Group open to `0.0.0.0/0` |
| Over-permissive identity | Broad RBAC role assignment | Over-permissive IAM policy |
| Public data | Storage account public access | Public S3 bucket |
| *(stretch)* Logging disabled | Disable diagnostic setting | Disable CloudTrail/Config |

*The AWS column documents how the design would mirror to a second cloud if extended later. It is
not required to consider the project complete.*

---

## Prerequisites

- **Terraform** ≥ 1.6
- **Python** ≥ 3.10
- **Azure CLI** (`az login`) with a personal/lab subscription
- *(detection)* **Prowler** ≥ 4.x
- *(optional future / AWS extension)* **AWS CLI** (`aws configure`) with a lab account

## Quick start (Azure MVP)

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
python -m security_monkey.monkey --cloud azure --dry-run

# 5. Inject a random misconfiguration (asks for confirmation)
python -m security_monkey.monkey --cloud azure

# 6. Run detection (Prowler + check Defender / Policy) ... fill the matrix

# 7. Revert everything the monkey did
python -m security_monkey.teardown --cloud azure

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
