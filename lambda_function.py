import boto3
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    try:
        # 1. Safely extract the bucket name from the CloudTrail event
        detail = event.get('detail', {})
        request_parameters = detail.get('requestParameters', {})
        bucket_name = request_parameters.get('bucketName')

        if not bucket_name:
            print("No bucket name found in event. Exiting.")
            return {'status': 200, 'message': 'Ignored: No bucket name.'}

        print(f"Threat detected. Checking current state for bucket: {bucket_name}")

        # ==========================================
        # 2. THE STATE BREAKER (Check Reality First)
        # ==========================================
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})

            # Check if all 4 security pillars are ALREADY fully active
            is_secure = (
                config.get('BlockPublicAcls') == True and
                config.get('IgnorePublicAcls') == True and
                config.get('BlockPublicPolicy') == True and
                config.get('RestrictPublicBuckets') == True
            )

            if is_secure:
                # LOOP BROKEN: The bucket is safe. Do nothing.
                print("STATE BREAKER TRIPPED: Bucket is already perfectly secure.")
                print("Exiting function peacefully to prevent infinite loops.")
                return {'status': 200, 'message': 'Idempotent exit. No action needed.'}
            
            else:
                print("Bucket is partially exposed. Proceeding with hard remediation.")

        except s3.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                print("Bucket is completely exposed (No config found). Proceeding with remediation.")
            else:
                raise e # Re-throw unexpected errors

        # ==========================================
        # 3. APPLY REMEDIATION (Lock it down)
        # ==========================================
        print(f"Applying strict Public Access Block to {bucket_name}...")
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        print("Remediation successful. Bucket locked.")
        return {'status': 200, 'message': 'Bucket secured successfully.'}

    except Exception as e:
        print(f"Error processing event: {str(e)}")
        return {'status': 500, 'message': str(e)}