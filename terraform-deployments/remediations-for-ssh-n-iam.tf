provider "aws" {
  region = "us-east-1"
}

# Secure Security Group - Restrict SSH Access to Home IP
resource "aws_security_group_rule" "remove_ssh_open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  security_group_id = aws_security_group.vizh_sg.id
  cidr_blocks = ["0.0.0.0/0"]

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_security_group_rule" "add_home_ip_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  security_group_id = aws_security_group.vizh_sg.id
  cidr_blocks = ["YOUR_HOME_IP/32"]  # Replace with actual home IP

  lifecycle {
    create_before_destroy = true
  }
}

# Remove Overly Permissive IAM Role Policies
resource "aws_iam_role_policy_attachment" "remove_ec2_full_access" {
  role       = aws_iam_role.vizh_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_iam_role_policy_attachment" "remove_s3_full_access" {
  role       = aws_iam_role.vizh_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"

  lifecycle {
    prevent_destroy = false
  }
}

# Secure S3 Bucket (if not already created)
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-mc-2-9-25"  # Replace with unique bucket name
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls   = true
  ignore_public_acls  = true
  block_public_policy = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Least Privilege IAM Policy (EC2 only for specific instance, S3 only for one bucket)
resource "aws_iam_policy" "least_privilege" {
  name        = "vizh-limited-access2"
  description = "Restrict EC2 and S3 access"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ec2:*"
        Resource = "arn:aws:ec2:us-east-1:903719520805:instance/i-0543ffa7e084d6f8c"
      },
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = [
          "arn:aws:s3:::my-secure-bucket-mc-2-9-25",
          "arn:aws:s3:::my-secure-bucket-mc-2-9-25/*"
        ]
      }
    ]
  })
}

# Attach the Least Privilege IAM Policy
resource "aws_iam_role_policy_attachment" "attach_least_privilege" {
  role       = aws_iam_role.vizh_role.name
  policy_arn = aws_iam_policy.least_privilege.arn
}
