# Detection layer

How each injected misconfiguration is detected, per control plane.

## Prowler (open-source CNAPP)

```bash
# Uses your `az login` session
prowler azure --subscription-ids <sub-id> --output-directory detection/prowler/output
```

Prowler output (OCSF/JSON/HTML) is gitignored under `detection/prowler/output/`; copy the
relevant finding summaries into `results/` for the matrix.

## Azure native

- **Defender for Cloud (CSPM, free tier):** check Recommendations for the lab RG after an
  injection. Note the recommendation name + severity + time-to-surface.
- **Azure Policy:** definitions live in `detection/azure-policy/`. Assign at the lab RG scope.
  See that folder for a `deployIfNotExists` remediation example.

## What to capture per injection (feeds the matrix)

| Field | Notes |
|---|---|
| Detected? | yes / no per control |
| Time to detect | injection timestamp → finding timestamp = MTTD |
| Severity | as reported by the control |
| Auto-remediated? | if a Policy/Config rule fixed it, record MTTR |
