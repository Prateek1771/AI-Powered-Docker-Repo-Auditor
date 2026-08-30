terraform {
  required_version = ">= 1.7.0"

  # Deliberately empty. The bucket is per-account, so a committed value is
  # either wrong for whoever clones this or points at someone else's bucket.
  # Supply it with -backend-config at init time.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}
