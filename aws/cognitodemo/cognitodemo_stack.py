from aws_cdk import core
from aws_cdk.aws_cognito import CfnIdentityPool, CfnIdentityPoolRoleAttachment, \
    CfnUserPoolGroup, CfnUserPoolUser, \
    CfnUserPoolUserToGroupAttachment, CfnUserPool, CfnUserPoolDomain, CfnUserPoolClient, UserPool, MfaSecondFactor, Mfa
from aws_cdk.aws_iam import Role, WebIdentityPrincipal, PolicyDocument, PolicyStatement, Effect
from aws_cdk.aws_s3 import Bucket
from aws_cdk.core import CfnOutput, RemovalPolicy, Fn, Aws


class CognitoDemoStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, *, login_domain_prefix: str, username: str, s3_bucket_name: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        user_pool = self._create_user_pool(login_domain_prefix)
        client = self._create_user_pool_client(user_pool)
        user = self._create_user_pool_user(user_pool, username)
        identity_pool = self._create_identity_pool(user_pool, client)
        s3_bucket = self._create_s3_bucket(s3_bucket_name)
        s3_access_role = self._create_s3_access_role(identity_pool, s3_bucket)
        self._configure_user_groups(user_pool, user, s3_access_role)

    def _create_user_pool(self, domain_prefix: str) -> CfnUserPool:
        # UserPool will unnecessarily create a role for SMS sending: https://github.com/aws/aws-cdk/issues/6943
        # But such a role is required by CloudFormation to be able to enable MFA (even if it's only OTP): https://github.com/awsdocs/aws-cloudformation-user-guide/issues/73
        # And it's not actually possible to configure only OTP MFA if there's a SMS configuration
        user_pool = UserPool(self, 'UserPool',
                             mfa=Mfa.REQUIRED,
                             mfa_second_factor=MfaSecondFactor(otp=True, sms=True),
                             user_pool_name='cognito-demo',
                             self_sign_up_enabled=True)
        user_pool_cfn = user_pool.node.default_child

        user_pool_domain = CfnUserPoolDomain(self, 'CognitoDomain',
                                             domain=domain_prefix,
                                             user_pool_id=user_pool_cfn.ref)

        CfnOutput(self, 'PROVIDER_NAME', value=user_pool_cfn.attr_provider_name)
        domain_name = Fn.join('.', [user_pool_domain.ref, 'auth', Aws.REGION, 'amazoncognito.com'])
        CfnOutput(self, 'COGNITO_URL', value=Fn.join('', ['https://', domain_name]))

        return user_pool_cfn

    def _create_user_pool_client(self, user_pool: CfnUserPool) -> CfnUserPoolClient:
        client = CfnUserPoolClient(self, 'CognitoDemoClient',
                                   user_pool_id=user_pool.ref,
                                   client_name='cognito-demo-client',
                                   generate_secret=True,
                                   supported_identity_providers=['COGNITO'],
                                   allowed_o_auth_flows_user_pool_client=True,
                                   allowed_o_auth_flows=['code'],
                                   allowed_o_auth_scopes=['openid', 'aws.cognito.signin.user.admin'],
                                   callback_ur_ls=['http://localhost:5000/redirect_uri'])

        CfnOutput(self, 'CLIENT_ID', value=client.ref)
        CfnOutput(self, 'CLIENT_SECRET', value=client.attr_client_secret)

        return client

    def _create_identity_pool(self, user_pool: CfnUserPool, client: CfnUserPoolClient) -> CfnIdentityPool:
        cognito_provider = CfnIdentityPool.CognitoIdentityProviderProperty(
            client_id=client.ref,
            provider_name=user_pool.attr_provider_name,
            server_side_token_check=True)

        identity_pool = CfnIdentityPool(self, 'IdentityPool',
                                        allow_unauthenticated_identities=False,
                                        identity_pool_name='cognito-demo',
                                        cognito_identity_providers=[cognito_provider])
        CfnIdentityPoolRoleAttachment(self, 'IdentityPoolRoleAttachment',
                                      identity_pool_id=identity_pool.ref,
                                      roles={},
                                      role_mappings={
                                          'cognito-user-pool': CfnIdentityPoolRoleAttachment.RoleMappingProperty(
                                              type='Token',
                                              ambiguous_role_resolution='Deny',
                                              identity_provider=Fn.join(':', [user_pool.attr_provider_name, client.ref])
                                          )
                                      })

        CfnOutput(self, 'IDENTITY_POOL_ID', value=identity_pool.ref)

        return identity_pool

    def _create_user_pool_user(self, user_pool: CfnUserPool, username: str) -> CfnUserPoolUser:
        user = CfnUserPoolUser(self, 'DemoUser',
                               user_pool_id=user_pool.ref,
                               desired_delivery_mediums=[],
                               message_action='SUPPRESS',
                               username=username)

        CfnOutput(self, 'USERNAME', value=user.username)

        return user

    def _create_s3_bucket(self, bucket_name: str) -> Bucket:
        bucket = Bucket(self, 'DemoBucket', bucket_name=bucket_name, removal_policy=RemovalPolicy.DESTROY)

        CfnOutput(self, 'S3_BUCKET_NAME', value=bucket.bucket_name)

        return bucket

    def _create_s3_access_role(self, identity_pool: CfnIdentityPool, s3_bucket: Bucket) -> Role:
        role = Role(self, 'DemoRole',
                    role_name='CognitoDemoBucketAccess',
                    assumed_by=WebIdentityPrincipal('cognito-identity.amazonaws.com', conditions={
                        'StringEquals': {
                            'cognito-identity.amazonaws.com:aud': identity_pool.ref
                        }
                    }),
                    inline_policies={
                        'ListBucket': PolicyDocument(statements=[
                            PolicyStatement(effect=Effect.ALLOW, actions=['s3:ListBucket'],
                                            resources=[s3_bucket.bucket_arn])
                        ])
                    })

        CfnOutput(self, 'ROLE_ARN', value=role.role_arn)

        return role

    def _configure_user_groups(self, user_pool: CfnUserPool, user: CfnUserPoolUser, s3_access_role: Role) -> None:
        group_with_access = CfnUserPoolGroup(self, 'GroupWithS3BucketAccess',
                                             group_name='GroupWithS3BucketAccess',
                                             user_pool_id=user_pool.ref,
                                             role_arn=s3_access_role.role_arn)

        group_without_access = CfnUserPoolGroup(self, 'GroupWithoutAccess',
                                                group_name='GroupWithoutAccess',
                                                user_pool_id=user_pool.ref)

        for i, group in enumerate([group_with_access, group_without_access]):
            CfnUserPoolUserToGroupAttachment(self, f'UserGroupAttachment{i}',
                                             group_name=group.ref,
                                             username=user.username,
                                             user_pool_id=user_pool.ref)
