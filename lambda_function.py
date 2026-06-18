import boto3
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    try:
        # 1. Parse the Event Details
        detail = event.get('detail', {})
        event_name = detail.get('eventName', '')
        request_parameters = detail.get('requestParameters', {})
        bucket_name = request_parameters.get('bucketName')

        if not bucket_name:
            print("No bucket name found in event. Exiting.")
            return {'status': 200, 'message': 'Ignored: No bucket name.'}

        print(f"🚨 Threat detected! Event: {event_name} on Bucket: {bucket_name}")

        # ==========================================
        # 2. THE ROUTER (Determine the Threat Type)
        # ==========================================
        if 'PublicAccessBlock' in event_name:
            return remediate_public_access(bucket_name)
            
        elif 'PutBucketVersioning' in event_name:
            return remediate_versioning(bucket_name)
            
        else:
            print(f"Unrecognized event: {event_name}. No action taken.")
            return {'status': 200, 'message': 'Ignored: Unrecognized event.'}

    except Exception as e:
        print(f"Error processing event: {str(e)}")
        return {'status': 500, 'message': str(e)}


# ==========================================
# 3. THREAT 1: PUBLIC ACCESS STATE BREAKER
# ==========================================
def remediate_public_access(bucket_name):
    print(f"Checking current state for Public Access on: {bucket_name}")
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response.get('PublicAccessBlockConfiguration', {})
        
        is_secure = (
            config.get('BlockPublicAcls') == True and
            config.get('IgnorePublicAcls') == True and
            config.get('BlockPublicPolicy') == True and
            config.get('RestrictPublicBuckets') == True
        )
        if is_secure:
            print("STATE BREAKER TRIPPED: Public Access is already perfectly secure.")
            return {'status': 200, 'message': 'Idempotent exit.'}
            
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            print("Bucket is completely exposed. Proceeding with remediation.")
        else:
            raise e

    print(f"Applying strict Public Access Block to {bucket_name}...")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
        }
    )
    print("Remediation successful. Public Access locked.")
    return {'status': 200, 'message': 'Public Access secured.'}


# ==========================================
# 4. THREAT 2: VERSIONING STATE BREAKER
# ==========================================
def remediate_versioning(bucket_name):
    print(f"Checking current state for Versioning on: {bucket_name}")
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    status = response.get('Status')

    if status == 'Enabled':
        print("STATE BREAKER TRIPPED: Versioning is already Enabled.")
        return {'status': 200, 'message': 'Idempotent exit.'}
    
    print(f"Versioning is currently {status}. Applying remediation...")
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    print("Remediation successful. Versioning Enabled.")
    return {'status': 200, 'message': 'Versioning enabled.'}