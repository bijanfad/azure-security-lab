# Detection-Coverage Matrix

The headline deliverable. For each injected misconfiguration, record whether each control
detected it, how long it took (MTTD), and whether it was auto-remediated (MTTR).

Legend: ✅ detected · ❌ missed · ⏳ MTTD · 🔧 auto-remediated (MTTR) · — n/a

| Misconfig class | Injector | Defender for Cloud | Azure Policy | Prowler |
|---|---|---|---|---|
| Network exposure | `azure-nsg-open` | _tbd_ | _tbd_ | _tbd_ |
| Public data | `azure-storage-public` | _tbd_ | _tbd_ | _tbd_ |
| Over-permissive identity | `azure-rbac-broad` | _tbd_ | _tbd_ | _tbd_ |

## Notes / observations

- _Fill in coverage gaps and MTTR numbers as runs complete._
