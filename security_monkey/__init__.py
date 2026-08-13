"""Security Monkey — injects controlled cloud misconfigurations for detection testing.

Everything here is scoped to an isolated lab (by subscription + resource group + prefix).
The injectors WEAKEN a deliberately secure baseline so native controls and Prowler can be
measured against a known ground truth. See CLAUDE.md for the full methodology.
"""

__version__ = "0.1.0"
