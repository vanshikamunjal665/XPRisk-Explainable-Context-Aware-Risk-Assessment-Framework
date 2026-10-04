# ===========================================================================
# XPRisk Phase 3 - INTENTIONALLY INSECURE IaC (Checkov target)
#
# ###########################################################################
# #  DELIBERATELY VULNERABLE STATIC-ANALYSIS FIXTURE. DO NOT APPLY.        #
# #  terraform apply MUST NEVER be run against this configuration.         #
# #  It exists only so Checkov has a deterministic, attributable target.   #
# ###########################################################################
#
# Expected Checkov findings:
#   CKV_AWS_19   S3 bucket server-side encryption disabled
#   CKV_AWS_20   S3 bucket ACL allows public access
#   CKV_AWS_21   S3 versioning disabled
#   CKV_AWS_144  S3 public access block missing
#   CKV_AWS_18   S3 access logging disabled
#   CKV_AWS_24   security group allows SSH (22) from 0.0.0.0/0
#   CKV_AWS_23   security group allows all traffic from 0.0.0.0/0
#   CKV_AWS_286  IAM policy grants wildcard actions
#   CKV_AWS_355  IAM policy grants wildcard resource
#
# No credentials, apply instructions, or real account identifiers appear here.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "insecure" {
  bucket = "xprisk-phase3-insecure-test-fixture"
  # CKV_AWS_20: public ACL.
  acl = "public-read"
}

# CKV_AWS_144: intentionally no aws_s3_bucket_public_access_block.

# CKV_AWS_19 / CKV_AWS_21 / CKV_AWS_18: no encryption/versioning/logging
# resources are declared on purpose.

resource "aws_security_group" "insecure" {
  name = "xprisk-phase3-insecure-sg"

  ingress {
    # CKV_AWS_24: SSH open to the world.
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    # CKV_AWS_23: everything open to the world.
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "insecure" {
  name = "xprisk-phase3-wildcard"
  # CKV_AWS_286 + CKV_AWS_355: wildcard action on wildcard resource.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
