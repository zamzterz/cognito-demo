import argparse
import json
import sys
from getpass import getpass

import boto3
from qrcode import QRCode

cognito_client = boto3.client('cognito-idp')


def auth_req(client_id, username, password):
    return cognito_client.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME': username, 'PASSWORD': password},
        ClientId=client_id
    )


def authenticate(client_id, username):
    response = None
    password = None
    while not response:
        try:
            password = getpass()
            response = auth_req(client_id, username, password)
        except cognito_client.exceptions.NotAuthorizedException:
            print('Incorrect password, please try again.')
            pass
        except cognito_client.exceptions.PasswordResetRequiredException:
            print('You need to reset your password.')
            password = forgot_password_flow(client_id, username)
            response = auth_req(client_id, username, password)

    return response, password


def forgot_password_flow(client_id, username):
    response = cognito_client.forgot_password(
        ClientId=client_id,
        Username=username
    )
    print(json.dumps(response['CodeDeliveryDetails']))
    confirmation_code = input('Enter the confirmation code: ')

    password_ok = False
    while not password_ok:
        new_password = getpass('Enter new password: ')
        confirmed_password = getpass('Confirm new password: ')
        if new_password == confirmed_password:
            password_ok = True

    cognito_client.confirm_forgot_password(
        ClientId=client_id,
        Username=username,
        ConfirmationCode=confirmation_code,
        Password=confirmed_password
    )
    print('Password successfully changed')
    return confirmed_password


def second_factor_auth(client_id, username, challenge_name, session):
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

    cognito_client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
        AccessToken=response['AuthenticationResult']['AccessToken']
    )

    return response


def totp_setup(session, client_id, username, password):
    response = cognito_client.associate_software_token(Session=session)
    secret = response['SecretCode']
    qr_uri = f'otpauth://totp/Cognito:{username}?secret={secret}&issuer=Cognito'
    qr = QRCode()
    qr.add_data(qr_uri)
    qr.make(fit=True)
    qr.print_ascii()

    user_code = input('Scan the QR code, then input the TOTP: ')
    response = cognito_client.verify_software_token(
        Session=response['Session'],
        UserCode=user_code
    )

    if response['Status'] != 'SUCCESS':
        print(f'Failed to verify MFA: {json.dumps(auth_response)}')
        sys.exit(1)

    token_response = auth_req(client_id, username, password)

    cognito_client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
        AccessToken=token_response['AuthenticationResult']['AccessToken']
    )

    return token_response


def print_auth_result(response):
    print(json.dumps(response['AuthenticationResult'], indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('client_id', type=str)
    parser.add_argument('username', type=str)
    args = parser.parse_args()

    auth_response, password = authenticate(args.client_id, args.username)

    challenge_name = auth_response.get('ChallengeName')
    if challenge_name in ['SOFTWARE_TOKEN_MFA', 'SMS_MFA']:
        token_response = second_factor_auth(args.client_id, args.username, challenge_name, auth_response['Session'])
        print_auth_result(token_response)
    elif challenge_name == 'MFA_SETUP':
        token_response = totp_setup(auth_response['Session'], args.client_id, args.username, password)
        print_auth_result(token_response)
    elif 'AuthenticationResult' in auth_response:
        print_auth_result(auth_response)
    else:
        print(f'Unknown response from Cognito: {json.dumps(auth_response)}')
        sys.exit(1)
