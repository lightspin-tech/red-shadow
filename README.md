![red-shadow](static/red-shadow.png)

# Red-Shadow
## Lightspin AWS IAM Vulnerability Scanner


### Description
Scan your AWS IAM Configuration for shadow admins in AWS IAM based on misconfigured deny policies not affecting users in groups discovered by Lightspin's Security Research Team.

The tool detects the misconfigurations in the following IAM Objects:

+ **Managed Policies**

+ **Users Inline Policies**

+ **Groups Inline Policies**

+ **Roles Inline Policies**


### Research Summary
AWS IAM evaluation logic for deny policies applied to groups do not work the same way as security engineers may be used to with Active Directory or other authorization mechanisms.

If a policy with a group resource has an explicit deny, this will only impact group actions, and not user actions, opening organizations up to misconfiguration and vulnerabilities if they assume the process to be the same as with Active Directory, for example.

Example for vulnerable json policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ProtectManagersByDeny",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "arn:aws:iam::123456789999:group/managers"
        }
    ]
}
```
In this example, the policy should deny any iam action done by users, groups or roles with that policy attached to, towards the group called managers.

The fact is that simple IAM action like ```iam:ChangePassword``` would work as the deny policy is ineffective.

[Link to the security research blog](https://blog.lightspin.io/aws-iam-groups-authorization-bypass)

### Detection

AWS IAM has a clear seperation between user object actions and group object actions.

The following list includes the user object actions the tool is scanning over deny policies affecting groups (besides wildcard):
```json
AWS_USER_ACTIONS = ["iam:CreateUser",
                     "iam:GetUser",
                     "iam:UpdateUser",
                     "iam:DeleteUser",
                     "iam:GetUserPolicy",
                     "iam:PutUserPolicy",
                     "iam:DeleteUserPolicy",
                     "iam:ListUserPolicies",
                     "iam:AttachUserPolicy",
                     "iam:DetachUserPolicy",
                     "iam:ListAttachedUserPolicies",
                     "iam:SimulatePrincipalPolicy",
                     "iam:GetContextKeysForPrincipalPolicy",
                     "iam:TagUser",
                     "iam:UpdateSSHPublicKey",
                     "iam:UntagUser",
                     "iam:GetSSHPublicKey",
                     "iam:ListUserTags",
                     "iam:DeleteSSHPublicKey",
                     "iam:GetLoginProfile",
                     "iam:GetAccessKeyLastUsed",
                     "iam:UpdateLoginProfile",
                     "iam:UploadSigningCertificate",
                     "iam:DeleteLoginProfile",
                     "iam:ListSigningCertificates",
                     "iam:CreateLoginProfile",
                     "iam:UpdateSigningCertificate",
                     "iam:EnableMFADevice",
                     "iam:DeleteSigningCertificate",
                     "iam:ResyncMFADevice",
                     "iam:ListServiceSpecificCredentials",
                     "iam:ListMFADevices",
                     "iam:ResetServiceSpecificCredential",
                     "iam:DeactivateMFADevice",
                     "iam:CreateServiceSpecificCredential",
                     "iam:ChangePassword",
                     "iam:UpdateServiceSpecificCredential",
                     "iam:CreateAccessKey",
                     "iam:DeleteServiceSpecificCredential",
                     "iam:ListAccessKeys",
                     "iam:PutUserPermissionsBoundary",
                     "iam:UpdateAccessKey",
                     "iam:DeleteUserPermissionsBoundary",
                     "iam:DeleteAccessKey",
                     "iam:ListGroupsForUser",
                     "iam:ListSSHPublicKeys",
                     "iam:UploadSSHPublicKey"]
```

Many of the user object actions mentioned above can easily lead to a privilege escalation or compromising the account, such as reseting the admin's password, deactivating the root account mfa and more.

### Requirements
Red-Shadow is built with Python 3 and Boto3.

The tool requires:
- [IAM User with Access Key in OS Env](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
- [Sufficient permissions for the IAM User to run the scanner](red-shadow-policy.json)
- Python 3 and pip3 installed

### Installation
```bash
sudo git clone https://github.com/lightspin-tech/red-shadow.git
cd red-shadow
pip3 install -r requirements.txt
```
### Usage
```bash
python3 red-shadow.py
```

### Analyze Results

The results discovers any IAM object that is vulnerable to such authorization bypass in AWS.

Example of results output:
```console
++ Starting Red-Shadow ++

++ AWS IAM Vulnerability Scanner
++ Red Shadow scans for shadow admins in AWS IAM based on misconfigured deny policies not affecting users in groups

Step 1: Searching for IAM Group misconfigurations in managed policies
Found potential misconfiguration at arn:aws:iam::123456789999:policy/ProtectManagers
Progress: |██████████████████████████████████████████████████| 100.0% Complete
Step 2: Searching for IAM Group misconfigurations in Users inline policies
Progress: |██████████████████████████████████████████████████| 100.0% Complete
Step 3: Searching for IAM Group misconfigurations in Groups inline policies
Progress: |██████████████████████████████████████████████████| 100.0% Complete
Step 4: Searching for IAM Group misconfigurations in Roles inline policies
Progress: |██████████████████████████████████████████████████| 100.0% Complete
Done
```

In this console output we can see that our ProtectManagers deny policy is ineffective and vulnerable to attacks such as privilege escalation mentioned above.

## License
This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-shadow/blob/main/LICENSE).