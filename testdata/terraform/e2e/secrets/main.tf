# Every value here is fake. The input document must never print them.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    bucket     = "example-tf-state"
    key        = "state/terraform.tfstate"
    access_key = "fake-backend-access-key"
  }
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = "fake-sensitive-default"
}

resource "aws_db_instance" "main" {
  identifier        = "example-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "app"
  password          = var.db_password
}

resource "aws_ssm_parameter" "note" {
  name  = "/example/note"
  type  = "String"
  value = var.db_password
}

# A literal under a credential-like name: redacted by its name.
resource "aws_rds_cluster" "main" {
  cluster_identifier = "example-cluster"
  engine             = "aurora-postgresql"
  master_username    = "app"
  master_password    = "fake-literal-cluster-password"
}

# A literal with a secret's form under a neutral name: redacted by its pattern.
resource "aws_ssm_parameter" "key" {
  name  = "/example/key"
  type  = "SecureString"
  value = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANfakekeymaterial\n-----END PRIVATE KEY-----" # iace:fake-secret
}
