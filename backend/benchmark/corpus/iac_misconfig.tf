# Benchmark corpus: Terraform misconfigurations.
# `VULN:<type>` marks a flaw expected on that line; findings elsewhere are false positives.

resource "aws_s3_bucket" "logs" {
  bucket = "my-app-logs"
  acl    = "public-read" # VULN:tf_public_bucket
}

resource "aws_s3_bucket" "private_data" {
  bucket = "my-app-private"
  acl    = "private"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULN:tf_open_ingress
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal" {
  name = "internal"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"          # VULN:tf_hardcoded_credential VULN:hardcoded_secret
  secret_key = "${var.aws_secret_access_key}"
}
