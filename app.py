import dataclasses
import logging

import boto3
import botocore
import flask
from flask import Flask, request, redirect, render_template, url_for
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from flask_pyoidc.user_session import UserSession

from cognitodemo import s3
from cognitodemo.access import AwsAccesser
from cognitodemo.mfa import get_mfa_challenge, verify_mfa_challenge, user_has_software_token_mfa

app = Flask(__name__)

app.config.from_envvar('COGNITO_DEMO_SETTINGS')
app.config.update({'OIDC_REDIRECT_URI': 'http://localhost:5000/redirect_uri',
                   'DEBUG': True})

issuer = f'https://{app.config["PROVIDER_NAME"]}'
cognito_config = ProviderConfiguration(
    provider_metadata=ProviderMetadata(
        issuer=issuer,
        authorization_endpoint=f'{app.config["COGNITO_URL"]}/oauth2/authorize',
        jwks_uri=f'{issuer}/.well-known/jwks.json',
        token_endpoint=f'{app.config["COGNITO_URL"]}/oauth2/token',
    ),
    client_metadata=ClientMetadata(app.config["CLIENT_ID"], app.config["CLIENT_SECRET"]),
    auth_request_params={
        'scope': ['openid', 'aws.cognito.signin.user.admin']  # scope required to update MFA for logged-in user
    }
)
auth = OIDCAuthentication({'cognito': cognito_config})

aws_accesser = AwsAccesser(app.config['AWS_ACCOUNT_ID'], app.config['IDENTITY_POOL_ID'], app.config['PROVIDER_NAME'])


@app.route('/')
@auth.oidc_auth('cognito')
def index():
    user_session = UserSession(flask.session)

    if not user_has_software_token_mfa(user_session.access_token):
        challenge = get_mfa_challenge(user_session.access_token)
        flask.session['mfa-challenge'] = challenge
        return redirect(url_for('verify_mfa'), code=303)

    bucket_content = []
    if 'aws-credentials' in flask.session:
        session = boto3.Session(**flask.session['aws-credentials'])
        bucket_prefix = app.config['S3_PREFIX_PER_ROLE'].get(flask.session.get('aws-role', None))
        try:
            bucket_content = [obj.key for obj in s3.list_bucket(session, app.config['S3_BUCKET_NAME'], bucket_prefix)]
        except botocore.exceptions.ClientError as error:
            flask.flash('You don\'t have access')

    return render_template(
        'index.html',
        user_groups=user_session.id_token['cognito:groups'],
        user_roles=user_session.id_token['cognito:roles'],
        current_role=flask.session.get('aws-role'),
        s3_bucket=app.config['S3_BUCKET_NAME'],
        s3_bucket_content=bucket_content
    )


@app.route('/switch-role', methods=['POST'])
def switch_role():
    requested_role = request.form['role']

    if not requested_role:
        if 'aws-credentials' in flask.session:
            del flask.session['aws-credentials']
            del flask.session['aws-role']
            flask.flash('No role assumed')
        return redirect(url_for('index'), code=303)

    user_session = UserSession(flask.session)
    if requested_role not in user_session.id_token.get('cognito:roles', []):
        flask.flash(f'Failed to switch role')
        return redirect(url_for('index'), code=303)

    aws_credentials = aws_accesser.get_credentials(user_session.id_token_jwt, requested_role)
    flask.session['aws-credentials'] = dataclasses.asdict(aws_credentials)
    flask.session['aws-role'] = requested_role

    flask.flash(f'Switched role to {requested_role}')
    return redirect(url_for('index'), code=303)


@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    def show_mfa(user_session, code):
        service_name = 'Cognito demo'
        user_email = user_session.id_token['cognito:username']
        qr_uri = f'otpauth://totp/{service_name}:{user_email}?secret={code}&issuer={service_name}'
        return render_template('verify-mfa.html', secret=code, qr_uri=qr_uri)

    user_session = UserSession(flask.session)
    mfa_challenge = flask.session.get('mfa-challenge', None)
    if not mfa_challenge:
        return 'No MFA verification in progress, please try to login again.'

    if request.method == 'GET':
        return show_mfa(user_session, mfa_challenge)

    user_code = request.form['code']
    if len(user_code) != 6:
        flask.flash('Code must be 6 chars.')
        return show_mfa(user_session, mfa_challenge)

    if not verify_mfa_challenge(user_session.access_token, user_code):
        flask.flash('MFA verification failed, please try again.')
        return show_mfa(user_session, mfa_challenge)

    del flask.session['mfa-challenge']
    return redirect(url_for('index'), code=303)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run()
