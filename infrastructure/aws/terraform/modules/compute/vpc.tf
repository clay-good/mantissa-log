resource "aws_security_group" "lambda" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.name_prefix}-lambda-sg"
  description = "Security group for Mantissa Log Lambda functions"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.name_prefix}-lambda-sg"
  }
}
