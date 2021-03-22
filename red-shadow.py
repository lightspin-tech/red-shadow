import re

import boto3

AWS_GROUP_PATTERN = 'arn:aws:iam::\\d+:group/.*'
AWS_USER_ACTIONS = ["*", "iam:CreateUser", "iam:GetUser", "iam:UpdateUser", "iam:DeleteUser", "iam:GetUserPolicy",
                    "iam:PutUserPolicy", "iam:DeleteUserPolicy", "iam:ListUserPolicies", "iam:AttachUserPolicy",
                    "iam:DetachUserPolicy", "iam:ListAttachedUserPolicies", "iam:SimulatePrincipalPolicy",
                    "iam:GetContextKeysForPrincipalPolicy", "iam:TagUser", "iam:UpdateSSHPublicKey", "iam:UntagUser",
                    "iam:GetSSHPublicKey", "iam:ListUserTags", "iam:DeleteSSHPublicKey", "iam:GetLoginProfile",
                    "iam:GetAccessKeyLastUsed", "iam:UpdateLoginProfile", "iam:UploadSigningCertificate",
                    "iam:DeleteLoginProfile", "iam:ListSigningCertificates", "iam:CreateLoginProfile",
                    "iam:UpdateSigningCertificate", "iam:EnableMFADevice", "iam:DeleteSigningCertificate",
                    "iam:ResyncMFADevice", "iam:ListServiceSpecificCredentials", "iam:ListMFADevices",
                    "iam:ResetServiceSpecificCredential", "iam:DeactivateMFADevice",
                    "iam:CreateServiceSpecificCredential", "iam:ChangePassword", "iam:UpdateServiceSpecificCredential",
                    "iam:CreateAccessKey", "iam:DeleteServiceSpecificCredential", "iam:ListAccessKeys",
                    "iam:PutUserPermissionsBoundary", "iam:UpdateAccessKey", "iam:DeleteUserPermissionsBoundary",
                    "iam:DeleteAccessKey", "iam:ListGroupsForUser", "iam:ListSSHPublicKeys", "iam:UploadSSHPublicKey"]


def is_group_misconfig(statement):

    if 'Effect' not in statement or 'Action' not in statement or 'Resource' not in statement:
        return False
    
    is_deny = statement['Effect'] == 'Deny'

    is_user_action = False
    for action in statement['Action']:
        if action in AWS_USER_ACTIONS:
            is_user_action = True

    is_group_resource = False
    if isinstance(statement['Resource'], list):
        for resource in statement['Resource']:
            if re.match(AWS_GROUP_PATTERN, resource):
                is_group_resource = True
    else:
        if re.match(AWS_GROUP_PATTERN, statement['Resource']):
            is_group_resource = True

    return is_deny and is_user_action and is_group_resource


def search_in_policy_document(document):
    if isinstance(document['Statement'], list):
        for statement in document['Statement']:
            if is_group_misconfig(statement):
                return True
    else:
        if is_group_misconfig(document['Statement']):
            return True

    return False


def search_in_policies(policies):
    for policy in policies:
        if search_in_policy_document(policy.policy_document):
            return True
    return False


def search_in_managed_policies(policies):
    total = len(list(policies))
    i = 0
    for policy in policies:
        i = i + 1
        print_progress_bar(i, total, prefix='Progress:', suffix='Complete', length=50)
        if search_in_policy_document(policy.default_version.document):
            print(f"Found potential misconfiguration at {policy.arn}")


def search_in_inline_policies(iterable_iam):
    total = len(list(iterable_iam))
    i = 0
    for iam_entity in iterable_iam:
        i = i + 1
        print_progress_bar(i, total, prefix='Progress:', suffix='Complete', length=50)
        if search_in_policies(iam_entity.policies.all()):
            print(f"Found potential misconfiguration at {iam_entity.arn}")


# Print iterations progress
def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
    # Print New Line on Complete
    if iteration == total:
        print()


if __name__ == '__main__':
    iam = boto3.resource('iam')
    print("++ Starting Red-Shadow ++")
    print("")
    print("++ AWS IAM Vulnerability Scanner")
    print("++ Red Shadow scans for shadow admins in AWS IAM based on misconfigured deny policies not affecting users in groups")
    print("")
    print("Step 1: Searching for IAM Group misconfigurations in managed policies")
    search_in_managed_policies(iam.policies.all())
    print("Step 2: Searching for IAM Group misconfigurations in Users inline policies")
    search_in_inline_policies(iam.users.all())
    print("Step 3: Searching for IAM Group misconfigurations in Groups inline policies")
    search_in_inline_policies(iam.groups.all())
    print("Step 4: Searching for IAM Group misconfigurations in Roles inline policies")
    search_in_inline_policies(iam.roles.all())
    print("Done")
