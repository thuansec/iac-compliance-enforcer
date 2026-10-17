variable "name" {
  type    = string
  default = "example-shared"
}

resource "aws_s3_bucket" "shared" {
  bucket = var.name
}
