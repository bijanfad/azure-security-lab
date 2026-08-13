# AWS lab module — Phase 2

Placeholder for the AWS mirror of the Azure lab (VPC/Security Group, S3 bucket, IAM test
user/role). Build this after the Azure MVP is complete, per the build order in `CLAUDE.md`.

Planned resources (secure baseline — injectors weaken them, teardown reverts):
- **VPC + Security Group** locked down (network-exposure injector opens `0.0.0.0/0`).
- **S3 bucket** with Public Access Block ON (public-data injector disables it).
- **IAM test user/role** with minimal policy (identity injector attaches an over-permissive one).

All resources tagged `project=security-lab`.
