provider "aws" {
  region = "us-east-1"
}

# Generate a new key pair
resource "aws_key_pair" "vizh_key" {
  key_name   = "vizh-keypair"
  public_key = file("~/.ssh/vizh-keypair.pub")  # Ensure you generate and provide a public key
}

# Create a security group with an insecure rule (SSH open to the internet)
resource "aws_security_group" "vizh_sg" {
  name        = "vizh-exposed-sg"
  description = "Security group allowing unrestricted SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # 🚨 Allows SSH from anywhere (highly insecure)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create an overly permissive IAM role
resource "aws_iam_role" "vizh_role" {
  name = "vizh-service-role-fullaccess"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Attach overly permissive policies to the IAM role
resource "aws_iam_role_policy_attachment" "ec2_full_access" {
  role       = aws_iam_role.vizh_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "s3_full_access" {
  role       = aws_iam_role.vizh_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# Create an instance profile and attach the role
resource "aws_iam_instance_profile" "vizh_profile" {
  name = "vizh-service-profile"
  role = aws_iam_role.vizh_role.name
}

# Create a KMS key with misconfigurations
resource "aws_kms_key" "vizh_kms" {
  description             = "Flawed KMS Key for EC2 encryption"
  enable_key_rotation     = false # Not enabling the key rotation (security risk)
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Principal = "*"
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

# Creating the EC2 instance with the misconfigured settings
resource "aws_instance" "vizh_instance" {
  ami                         = "ami-09d3b3274b6c5d4aa" # Amazon Linux 2 AMI (check for latest)
  instance_type               = "t2.micro"
  key_name                    = aws_key_pair.vizh_key.key_name
  iam_instance_profile        = aws_iam_instance_profile.vizh_profile.name
  associate_public_ip_address = true # This exposes instance to the internet

  vpc_security_group_ids = [aws_security_group.vizh_sg.id]

  root_block_device {
    encrypted = true
    kms_key_id = aws_kms_key.vizh_kms.arn
  }

  tags = {
    Name = "Vizh-Exposed-Instance"
  }
}

# Output values for reference
output "instance_id" {
  value = aws_instance.vizh_instance.id
}

output "public_ip" {
  value = aws_instance.vizh_instance.public_ip
}

output "security_group_id" {
  value = aws_security_group.vizh_sg.id
}

output "iam_role_name" {
  value = aws_iam_role.vizh_role.name
}

output "kms_key_id" {
  value = aws_kms_key.vizh_kms.id
}
