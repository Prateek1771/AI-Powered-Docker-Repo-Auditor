terraform {
  # Bounded at both ends. >= 1.10 is where S3 native state locking
  # (use_lockfile) arrived; the missing upper bound is why nothing caught that
  # 1.13 REMOVED the dynamodb_table backend argument CI was still passing.
  # See docs/AUDIT.md P4-4.
  required_version = ">= 1.10.0, < 2.0.0"

  # Deliberately empty. The bucket is per-account, so a committed value is
  # either wrong for whoever clones this or points at someone else's bucket.
  # Supply it with -backend-config at init time.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }

    # Generates the Redis auth token. A token nobody types is a token nobody
    # leaks into a chat window, and it means CI needs no second GitHub secret.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}
