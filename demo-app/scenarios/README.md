# XPRisk Phase 3 — Controlled Scenario Fixtures

These fixtures are the **intentional security-test cases** created in Phase 3.
They exist so that Trivy, Checkov, Gitleaks and SonarQube each have a clear,
deterministic, isolated target in Phase 4.

> ⚠️ All values are fake. Every "secret" is obviously a test-only placeholder.
> No real credentials appear anywhere in this tree.
> The Terraform fixtures under `infrastructure/scenarios/` must **never** be
> applied. Nothing in this directory is imported by the demo application or
> the XPRisk backend.

## Layout

```
demo-app/scenarios/
├── README.md                       (this file)
├── insecure/
│   ├── secrets/fake_secrets.env    Gitleaks target: fake, marked credentials
│   ├── Dockerfile.vulnerable       Trivy target: EOL base image, many CVEs
│   └── code/insecure_code.py       SonarQube target: insecure code patterns
└── clean/
    ├── secrets/no_secrets.env      Gitleaks clean counterpart (no secrets)
    ├── Dockerfile.clean            Trivy clean counterpart (maintained base)
    └── code/secure_code.py         SonarQube clean counterpart

infrastructure/scenarios/
├── insecure/main.tf                Checkov target: insecure AWS IaC
└── clean/main.tf                   Checkov clean counterpart (hardened)
```

## Rules

1. Each vulnerable fixture has a structurally comparable `clean` counterpart
   so a later run can show `insecure → controlled findings` vs
   `clean → no intentional findings`.
2. Fixtures are static-analysis targets. Do not build the vulnerable image,
   do not run its code, do not `terraform apply` anything.
3. Scanner integration (Trivy/Checkov/Gitleaks/SonarQube) is Phase 4 and is
   intentionally absent from this phase.
