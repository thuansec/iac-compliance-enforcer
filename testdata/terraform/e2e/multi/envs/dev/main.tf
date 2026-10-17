terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_s3_bucket" "dev" {
  bucket = "example-dev"
}

# Called with count = 0, so no tree instantiates it: it is scanned on its own as an orphan.
module "shared" {
  source = "../../modules/shared"
  count  = 0
}
