# Demo Infrastructure (IaC)

Terraform configuration for the XPRisk demo application. This is the target for
**Checkov**.

> ⚠️ **This configuration is intentionally insecure.** Every weakness below is
> deliberate and is a controlled test case for the XPRisk framework. Do not copy
> any part of it into a real environment. Do not run `terraform apply`.

## Layout

```
infrastructure/
└── terraform/
    ├── main.tf                  All resources, intentionally insecure
    ├── main.tf.example-vars    Example variable values (placeholders only)
    └── .terraform.lock.hcl     Provider version lock (tracked)
```

## Why the IaC lives here and not inside `demo-app/`

XPRisk scans **two** distinct kinds of asset:

1. Application code and container images → `demo-app/`
2. Infrastructure-as-code → `infrastructure/`

Keeping them at separate top-level paths means a scanner target is a single,
explicit directory. Checkov can therefore be pointed at `infrastructure/`
without also parsing Python, and Trivy can be pointed at `demo-app/` without
seeing Terraform. That separation is what makes the scanner configuration in
`.env.example` unambiguous.

## Expected Checkov findings

Each insecure pattern in `main.tf` is annotated inline with the Checkov check ID
it is expected to trigger, so the finding-to-cause mapping stays verifiable
during a demonstration.

| Resource | Insecure choice | Expected check |
|---|---|---|
| `aws_security_group.open_ssh` | SSH open to `0.0.0.0/0` | `CKV_AWS_24` |
| `aws_security_group.wide_open` | All traffic from `0.0.0.0/0` | `CKV_AWS_23` |
| `aws_s3_bucket.app` | `acl = "public-read"`, no versioning | `CKV_AWS_20`, `CKV_AWS_21` |
| `aws_s3_bucket.app` | no logging | `CKV_AWS_18` |
| `aws_s3_bucket.app` | no encryption | `CKV_AWS_19` |
| `aws_s3_bucket_public_access_block.missing` | public access not denied | `CKV_AWS_144`, `CKV_AWS_145` |
| `aws_instance.app` | `root_block_device { encrypted = false }` | `CKV_AWS_8` |
| `aws_instance.app` | `http_tokens = "optional"` (IMDSv1) | `CKV_AWS_79` |
| `aws_instance.app` | `monitoring = false` | `CKV_AWS_126` |
| `aws_db_instance.app` | `storage_encrypted = false` | `CKV_AWS_16` |
| `aws_db_instance.app` | `publicly_accessible = true` | `CKV_AWS_130` |
| `aws_db_instance.app` | `multi_az = false` | `CKV_AWS_17` |
| `aws_db_instance.app` | `backup_retention_period = 0` | `CKV_AWS_157` |
| `aws_iam_policy.overly_permissive` | `"Action": ["*"]` | `CKV_AWS_286` |
| `aws_iam_policy.overly_permissive` | `"Resource": ["*"]` | `CKV_AWS_355` |
| `aws_iam_user.admin` + attachment | admin policy on a user, not a role | `CKV_AWS_40` |
| `aws_dynamodb_table.sessions` | PITR disabled | `CKV_AWS_28` |

> Checkov's check catalogue changes between releases, so the exact set of IDs
> reported depends on the installed version. Treat the table above as the
> *expected causes*, not as a guaranteed output.

## No real credentials

The two credential-shaped variables, `admin_access_key` and
`db_master_password`, are declared with **no default value**, so `terraform plan`
cannot succeed unless an operator supplies something explicitly. Nothing
sensitive is committed, and `.tfvars` files are git-ignored.

The single occurrence of an AWS example key, `AKIAIOSFODNN7EXAMPLE`, is
referenced through a variable rather than written as a literal. It is the
canonical key from the AWS documentation and is not a valid credential.

## Validation

```powershell
terraform -chdir=infrastructure/terraform init -backend=false
terraform -chdir=infrastructure/terraform validate
terraform -chdir=infrastructure/terraform fmt -check
```

`validate` reports one **deprecation warning**, not an error:

```
Warning: Argument is deprecated
  with aws_s3_bucket.app
  195:   acl = "public-read"
```

That warning is expected and correct. The inline `acl` argument is deprecated in
AWS provider v5 in favour of a separate `aws_s3_bucket_acl` resource, and using
the inline form is exactly the pattern that produces the Checkov findings this
file exists to generate. It was left as-is deliberately.

## Scanning it with XPRisk

Checkov is configured in `.env.example`:

```
CHECKOV_FRAMEWORK=terraform
CHECKOV_SCAN_PATH=./infrastructure
```

Phase 4 wires this into the scanner adapter, which runs Checkov with an explicit
argument list and parses the JSON report into canonical XPRisk findings.