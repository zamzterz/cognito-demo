import dataclasses
from dataclasses import dataclass

import boto3
from boto3 import Session

cognito_client = boto3.client('cognito-identity')


@dataclass
class AwsCredentials:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str


class AwsAccesser:
    def __init__(self, aws_account_id, identity_pool_id, provider_name):
        self._aws_account_id = aws_account_id
        self._identity_pool_id = identity_pool_id
        self.provider_name = provider_name

    def get_credentials(self, id_token, role_arn=None):
        id_response = cognito_client.get_id(
            AccountId=self._aws_account_id,
            IdentityPoolId=self._identity_pool_id,
            Logins={self.provider_name: id_token}
        )
        # TODO handle any error

        request = {
            'IdentityId': id_response['IdentityId'],
            'Logins': {self.provider_name: id_token}
        }
        if role_arn:
            request['CustomRoleArn'] = role_arn

        credentials_response = cognito_client.get_credentials_for_identity(**request)
        # TODO handle any error

        return AwsCredentials(
            credentials_response['Credentials']['AccessKeyId'],
            credentials_response['Credentials']['SecretKey'],
            credentials_response['Credentials']['SessionToken']
        )

    def get_boto3_session(self, id_token, role_arn=None):
        aws_credentials = self.get_credentials(id_token, role_arn)
        return Session(**dataclasses.asdict(aws_credentials))
