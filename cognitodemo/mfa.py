import logging

import boto3
import botocore

cognito_client = boto3.client('cognito-idp')

logger = logging.getLogger(__name__)


def user_has_software_token_mfa(user_access_token):
    response = cognito_client.get_user(AccessToken=user_access_token)
    configured_mfas = response.get('UserMFASettingList', [])
    return 'SOFTWARE_TOKEN_MFA' in configured_mfas


def get_mfa_challenge(user_access_token):
    response = cognito_client.associate_software_token(AccessToken=user_access_token)
    return response['SecretCode']


def verify_mfa_challenge(user_access_token, user_code):
    try:
        response = cognito_client.verify_software_token(
            AccessToken=user_access_token,
            UserCode=user_code
        )
    except botocore.exceptions.ClientError as error:
        logger.info('Failed to verify MFA code: %s', error.response['Error'])
        return False

    if response['Status'] != 'SUCCESS':
        return False

    cognito_client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
        AccessToken=user_access_token
    )
    return True
