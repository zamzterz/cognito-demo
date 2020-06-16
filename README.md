# Cognito demo

This repo contains an example Python app that uses [AWS Cognito](https://aws.amazon.com/cognito/) for 
[authentication](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html) and
[authorization](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-integrating-user-pools-with-identity-pools.html)
to access protected AWS resources (an S3 bucket).

The app also showcases how to configure MFA TOTP the first time a user logs in; a step which isn't included in
Cognito's hosted UI's.


## AWS setup
Setup of the necessary AWS resources using the AWS CDK CLI is included in the `aws` directory. 
To run it, first install the AWS CDK CLI and the dependencies before deploying the CloudFormation stack:
```console
$ cd aws 
$ npm install -g aws-cdk
$ pipenv install
$ COGNITO_DEMO_LOGIN_DOMAIN_PREFIX='<login domain prefix>' COGNITO_DEMO_S3_BUCKET_NAME='<bucket name>' COGNITO_DEMO_USERNAME='<username>' cdk deploy
```

The required enviroment variables are:
* `COGNITO_DEMO_LOGIN_DOMAIN_PREFIX`: the domain prefix for the 
  [domain of the Cognito user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html).
* `COGNITO_DEMO_S3_BUCKET_NAME`: name of the S3 bucket to be created
* `COGNITO_DEMO_USERNAME`: username to use when logging in via AWS Cognito

All configuration parameters will be exported as outputs, except the `client_secret` which is not accessible via
CloudFormation. To get that, use the AWS CLI:
```console
$ aws cognito-idp describe-user-pool-client --user-pool-id <value> --client-id <value>
```

To be able to login with your chosen username, you must also set a password for the created user:
```console
$ aws cognito-idp admin-set-user-password --no-permanent --user-pool-id <value> --username <username> --password <value> 
```

## Running the app
The app is a simple Flask app which will list the contents of a preconfigured S3 bucket which the authenticated user
will gain access to by
[obtaining temporary AWS credentials](https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html)
associated with an IAM role from an Cognito Identity pool.

To run it, install the dependencies and update `settings.cfg` with your configuration. Then start the server:
```console
$ pipenv install
$ COGNITO_DEMO_SETTINGS=settings.cfg app.py
``` 

After that, visit http://localhost:5000 and login using the username and password you have configured.
It will ask you to configure TOTP MFA during the first login, so make sure to have an authenticator app.

Try uploading some content to the S3 bucket and refresh the page to view it! 🎉
