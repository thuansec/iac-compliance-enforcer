# Fifty instances whose user data is rendered from a template with %{ for } directives over the
# users, packages and mounts of each instance.
locals {
  users    = [for i in range(25) : { name = "user${i}", key = "ssh-ed25519 AAAAexample${i} user${i}@example.com" }]
  packages = [for i in range(40) : "package-${i}"]
  mounts   = { for i in range(10) : "/data/${i}" => "/dev/xvd${substr("bcdefghijk", i, 1)}" }
}

resource "aws_instance" "web" {
  count         = 50
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  user_data = templatefile("${path.module}/user_data.tftpl", {
    hostname = "web-${count.index}"
    users    = local.users
    packages = local.packages
    mounts   = local.mounts
  })
}
