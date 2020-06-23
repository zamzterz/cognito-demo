import json
import sys
from getpass import getpass

import boto3

cognito_client = boto3.client('cognito-idp')


def authenticate():
    response = None
    while not response:
        try:
            password = getpass()
            response = cognito_client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={'USERNAME': username, 'PASSWORD': password},
                ClientId=client_id,
            )
        except cognito_client.exceptions.NotAuthorizedException:
            print('Incorrect password, please try again.')
            pass

    return response


def second_factor_auth(challenge_name, session):
    response = None
    while not response:
        try:
            mfa_code = input('MFA code: ')
            response = cognito_client.respond_to_auth_challenge(
                ChallengeName=challenge_name,
                Session=session,
                ClientId=client_id,
                ChallengeResponses={
                    'USERNAME': username,
                    f'{challenge_name}_CODE': mfa_code
                })
        except cognito_client.exceptions.CodeMismatchException:
            print('Incorrect code, please try again.')
            pass

    return response


def print_auth_result(response):
    print(json.dumps(response['AuthenticationResult'], indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python cli.py <client id> <username>')
        sys.exit(1)

    client_id = sys.argv[1]
    username = sys.argv[2]

    auth_response = authenticate()

    challenge_name = auth_response.get('ChallengeName')
    if challenge_name in ['SOFTWARE_TOKEN_MFA', 'SMS_MFA']:
        token_response = second_factor_auth(challenge_name, auth_response['Session'])
        print_auth_result(token_response)
    elif 'AuthenticationResult' in auth_response:
        print_auth_result(auth_response)
    else:
        print(f'Unknown response from Cognito: {json.dumps(auth_response)}')
        sys.exit(1)
