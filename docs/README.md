# Docs

- **architecture.md** — architecture diagram + design rationale *(TODO; a text diagram is in the root README)*.
- **findings.md** — analysis write-up: methodology, the detection-coverage results, and where
  native controls and Prowler differ *(TODO — written after the first full run)*.

Findings write-up outline:
1. **Problem** — cloud misconfigurations as latent risk; testing posture, not just perimeters.
2. **Method** — controlled fault injection: inject → observe detection → measure coverage gaps.
3. **Design** — Terraform lab, the Security Monkey injector framework, the revert ledger.
4. **Detection** — Microsoft Defender for Cloud, Azure Policy, and open-source Prowler.
5. **Results** — the coverage matrix + MTTD/MTTR; where native controls missed findings.
6. **Takeaways** — coverage gaps and remediation observations.
