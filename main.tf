terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ==========================================
# 1. THE TARGET INFRASTRUCTURE
# ==========================================
resource "aws_s3_bucket" "secure_assets" {
  bucket_prefix = "mtech-secure-target-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "initial_lock" {
  bucket = aws_s3_bucket.secure_assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==========================================
# 2. AUTOMATIC CODE PACKAGING
# ==========================================
# Automatically zips your local Python file so Terraform can upload it
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "lambda_function.py"
  output_path = "remediation_payload.zip"
}

# ==========================================
# 3. AWS LAMBDA (The Executor)
# ==========================================
resource "aws_lambda_function" "s3_remediator" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "mtech-s3-auto-remediator"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 10
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}

# ==========================================
# 4. IAM PERMISSIONS
# ==========================================
resource "aws_iam_role" "lambda_exec_role" {
  name = "mtech-lambda-remediator-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_s3_policy" {
  name = "mtech-lambda-s3-policy"
  role = aws_iam_role.lambda_exec_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock"]
        Effect   = "Allow"
        Resource = "*" 
      },
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# ==========================================
# 5. EVENTBRIDGE (The Router/Tripwire)
# ==========================================
resource "aws_cloudwatch_event_rule" "s3_public_access_removed" {
  name        = "mtech-s3-public-access-alert"
  description = "Triggers Lambda when S3 Public Access Block is deleted via CloudTrail"

  event_pattern = jsonencode({
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["s3.amazonaws.com"],
      "eventName": ["DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock"]
    }
  })
}

resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_public_access_removed.name
  target_id = "TriggerS3Remediator"
  arn       = aws_lambda_function.s3_remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access_removed.arn
}
# --- ENFORCE VERSIONING (Ransomware Protection) ---
resource "aws_s3_bucket_versioning" "secure_versioning" {
  bucket = aws_s3_bucket.secure_assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- ENFORCE ENCRYPTION (Data Leak Protection) ---
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}