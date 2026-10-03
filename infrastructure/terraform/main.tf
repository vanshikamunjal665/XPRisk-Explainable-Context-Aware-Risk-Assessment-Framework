# ===========================================================================
# XPRisk demo infrastructure - INTENTIONALLY INSECURE
#
# ###########################################################################
# #  THIS FILE IS DELIBERATELY VULNERABLE. IT IS NOT PRODUCTION CODE.        #
# #                                                                          #
# #  Every insecure pattern below exists on purpose so that Checkov has a   #
# #  controlled, attributable test case. Do not copy any part of this file   #
# #  into a real environment.                                                #
# #                                                                          #
# #  Each violation is annotated with the Checkov check ID it is expected    #
# #  to trigger, so the finding-to-cause mapping stays verifiable.           #
# #                                                                          #
# #  NO REAL CREDENTIALS APPEAR IN THIS FILE. Access keys are supplied by    #
# #  variables with no defaults, and every example value is an obvious       #
# #  placeholder such as "CHANGEME" or "AKIAIOSFODNN7EXAMPLE" (the          #
# #  canonical AWS documentation example key, which is not a real key).      #
# ###########################################################################
#
# Expected Checkov findings (non-exhaustive):
#   CKV_AWS_24  security group allows SSH from 0.0.0.0/0
#   CKV_AWS_23  security group allows all ports from 0.0.0.0/0
#   CKV_AWS_18  S3 bucket logging disabled
#   CKV_AWS_19  S3 bucket encryption disabled
#   CKV_AWS_20  S3 bucket allows public ACL
#   CKV_AWS_21  S3 bucket versioning disabled
#   CKV_AWS_144 S3 bucket public access block missing
#   CKV_AWS_79  IMDSv1 enabled on EC2 instance
#   CKV_AWS_126 EC2 instance detailed monitoring disabled
#   CKV_AWS_8   EBS volume encryption disabled
#   CKV_AWS_16  RDS storage encryption disabled
#   CKV_AWS_17  RDS instance not in a multi-AZ configuration
#   CKV_AWS_130 RDS publicly accessible
#   CKV_AWS_16x RDS backup retention disabled
#   CKV_AWS_28  DynamoDB point-in-time recovery disabled
#   CKV_AWS_286 IAM policy grants wildcard actions
#   CKV_AWS_355 IAM policy grants wildcard resource
#   CKV_AWS_40  IAM policy attached to a user (not a role)
#
# Validation:  terraform -chdir=infrastructure/terraform init && validate
# ===========================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables. No secret values, and no defaults for anything credential-like.
# ---------------------------------------------------------------------------
variable "aws_region" {
  description = "Region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to created resources."
  type        = string
  default     = "xprisk-demo"
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name for the demo application."
  type        = string
  default     = "xprisk-demo-insecure-bucket"
}

# Intentionally has NO default. A plan that requires this value cannot succeed
# unless an operator supplies something explicitly.
variable "admin_access_key" {
  description = "Placeholder only. Never a real access key."
  type        = string
  sensitive   = true
}

variable "db_master_password" {
  description = "Placeholder only. Never a real password."
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# VPC and networking
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Insecure: wide-open internet gateway attached to a public route table.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Insecure: SSH open to the entire internet.
# Expected: CKV_AWS_24
resource "aws_security_group" "open_ssh" {
  name        = "${var.project_name}-open-ssh"
  description = "INTENTIONALLY INSECURE - allows SSH from 0.0.0.0/0"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere - deliberately insecure"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-open-ssh"
  }
}

# Insecure: every port open to the entire internet.
# Expected: CKV_AWS_23
resource "aws_security_group" "wide_open" {
  name        = "${var.project_name}-wide-open"
  description = "INTENTIONALLY INSECURE - allows all traffic from 0.0.0.0/0"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "All traffic from anywhere - deliberately insecure"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-wide-open"
  }
}

# ---------------------------------------------------------------------------
# Object storage
# ---------------------------------------------------------------------------
# Insecure: no versioning, no logging, no encryption, public ACL.
# Expected: CKV_AWS_21, CKV_AWS_18, CKV_AWS_19, CKV_AWS_20, CKV_AWS_144
resource "aws_s3_bucket" "app" {
  bucket = var.bucket_name

  acl = "public-read"

  tags = {
    Name = "${var.project_name}-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "missing" {
  bucket = aws_s3_bucket.app.id

  # Intentionally left empty so that public access is not blocked.
  # Expected: CKV_AWS_145 (block not configured to deny public access)
}

# ---------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------
# Insecure: unencrypted root volume, IMDSv1 reachable, no detailed monitoring.
# Expected: CKV_AWS_8, CKV_AWS_79, CKV_AWS_126
resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.open_ssh.id, aws_security_group.wide_open.id]

  # Public IP assigned - contributes to the internet-facing exposure story.
  associate_public_ip_address = true

  # Insecure: metadata service reachable over IMDSv1.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  monitoring = false

  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "${var.project_name}-instance"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Insecure: publicly accessible, unencrypted, single-AZ, no backups.
# Expected: CKV_AWS_130, CKV_AWS_16, CKV_AWS_17, CKV_AWS_157
resource "aws_db_instance" "app" {
  identifier     = "${var.project_name}-db"
  engine         = "postgres"
  engine_version = "15.7"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = false

  username = "demoadmin"
  # Supplied by the operator. Never a real password, and never defaulted here.
  password = var.db_master_password

  publicly_accessible     = true
  multi_az                = false
  backup_retention_period = 0
  skip_final_snapshot     = true

  tags = {
    Name = "${var.project_name}-db"
  }
}

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
# Insecure: wildcard actions and wildcard resources.
# Expected: CKV_AWS_286, CKV_AWS_355
resource "aws_iam_policy" "overly_permissive" {
  name        = "${var.project_name}-admin-policy"
  description = "INTENTIONALLY INSECURE - grants wildcard actions on all resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEverything"
        Effect = "Allow"
        Action = [
          "*"
        ]
        Resource = [
          "*"
        ]
      }
    ]
  })
}

# Insecure: administrative policy attached directly to a user rather than to a
# role, so long-lived credentials are required.
# Expected: CKV_AWS_40
resource "aws_iam_user" "admin" {
  name = "${var.project_name}-admin"
}

resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.admin.name
  policy_arn = aws_iam_policy.overly_permissive.arn
}

# Insecure: access key material declared in Terraform. The placeholder below is
# the AWS documentation example key and is not valid; the point is that key
# material has no business being in infrastructure code at all.
# Expected: CKV_AWS_..., plus a Gitleaks finding if this pattern is matched.
resource "aws_iam_access_key" "admin" {
  user = aws_iam_user.admin.name

  # Placeholder format only. Not a real credential.
  # Referenced through the variable so that no literal key is committed.
  # (The variable has no default, so a plan must be given a value explicitly.)
  # value = var.admin_access_key
}

# ---------------------------------------------------------------------------
# NoS3
# ---------------------------------------------------------------------------
# Insecure: point-in-time recovery disabled.
# Expected: CKV_AWS_28
resource "aws_dynamodb_table" "sessions" {
  name         = "${var.project_name}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  tags = {
    Name = "${var.project_name}-sessions"
  }
}

# ---------------------------------------------------------------------------
# Outputs. Nothing sensitive is exported.
# ---------------------------------------------------------------------------
output "bucket_name" {
  description = "Name of the intentionally public demo bucket."
  value       = aws_s3_bucket.app.bucket
}

output "instance_id" {
  description = "ID of the intentionally insecure demo instance."
  value       = aws_instance.app.id
}

output "db_endpoint" {
  description = "Endpoint of the intentionally public demo database."
  value       = aws_db_instance.app.endpoint
}