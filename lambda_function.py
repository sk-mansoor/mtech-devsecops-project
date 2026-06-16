import boto3
import json

# Initialize the S3 client
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    print("🚨 EventBridge Trigger Received! Analyzing CloudTrail API Event...")
    
    try:
        # Extract the bucket name from the CloudTrail API call details
        bucket_name = event['detail']['requestParameters']['bucketName']
        user_identity = event['detail']['userIdentity']['arn']
        
        print(f"⚠️ UNAUTHORIZED ACTION DETECTED: S3 Public Access Block modified on {bucket_name} by {user_identity}.")
        print("⚙️ Executing Immediate Serverless Remediation...")

        # Force the bucket back to an immutable secure state
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
    # 1. Force the bucket back to Private
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # 2. Force Versioning back ON (Defeat Ransomware)
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )       
        print(f"✅ SUCCESS: Security Baseline restored on {bucket_name}.")
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully remediated {bucket_name}')
        }
        
    except Exception as e:
        print(f"❌ Remediation Failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps('Failed to process event')
        }

