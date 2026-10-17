variable "prefix" {
  type = string
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-${var.prefix}-logs"
}

output "bucket" {
  value = aws_s3_bucket.logs.id
}
