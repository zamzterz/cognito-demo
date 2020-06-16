#!/usr/bin/env python3
import os

from aws_cdk import core

from cognitodemo.cognitodemo_stack import CognitoDemoStack

app = core.App()
CognitoDemoStack(app, 'cognito-demo', login_domain_prefix=os.environ['COGNITO_DEMO_LOGIN_DOMAIN_PREFIX'], username=os.environ['COGNITO_DEMO_USERNAME'], s3_bucket_name=os.environ['COGNITO_DEMO_S3_BUCKET_NAME'])

app.synth()
