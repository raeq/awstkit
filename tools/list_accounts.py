#!/usr/bin/env python3
"""
The CLI program "listaccounts"
"""
import logging
import sys

import boto3
from botocore.exceptions import ClientError


hierarchy: dict = dict()


def parent_details(client=None, childId: str = None) -> dict:
    parent = client.list_parents(ChildId = childId).get("Parents")[0]
    return client.describe_organizational_unit(OrganizationalUnitId = parent.get("Id")).get("OrganizationalUnit")


def account_details(client=None, child: dict = None) -> dict:
    if not child or not client:
        return dict()

    cid: str = child.get("Id")

    child["Parent"] = parent_details(client, cid)

    tags = client.list_tags_for_resource(
            ResourceId = cid).get("Tags")
    child["Tags"] = {i.get("Key"): i.get("Value") for i in tags}
    try:
        child["TAG_POLICY"] = client.describe_effective_policy(
                PolicyType = "TAG_POLICY",
                TargetId = cid).get("EffectivePolicy")
    except ClientError as e:
        child["TAG_POLICY"] = ""
    try:
        child["BACKUP_POLICY"] = client.describe_effective_policy(
                PolicyType = "BACKUP_POLICY",
                TargetId = cid).get("EffectivePolicy")
    except ClientError as e:
        child["BACKUP_POLICY"] = ""
    try:
        child["AISERVICES_OPT_OUT_POLICY"] = client.describe_effective_policy(
                PolicyType = "AISERVICES_OPT_OUT_POLICY",
                TargetId = cid).get("EffectivePolicy")
    except ClientError as e:
        child["AISERVICES_OPT_OUT_POLICY"] = ""
    try:
        child[
            "SERVICE_CONTROL_POLICY"] = client.list_policies_for_target(
                Filter = "SERVICE_CONTROL_POLICY",
                TargetId = cid).get("Policies")
    except ClientError as e:
        child["SERVICE_CONTROL_POLICY"] = ""
    try:
        child[
            "DelegatedServices"] = client.list_delegated_services_for_account(
                AccountId = cid).get("DelegatedServices")
    except ClientError as e:
        if e.response["Error"][
            "Code"] == "AccountNotRegisteredException":
            child["DelegatedServices"] = []
    return child


def list_all_accounts(profile: str = "") -> list:
    """
    Lists all accounts in an organization according to OU structure
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"Starting listaccounts cli method with profile '{profile}'.")

    session = boto3.session.Session(profile_name = profile)
    org = session.client("organizations")

    paginator = org.get_paginator('list_accounts')
    page_iterator = paginator.paginate()

    for page in page_iterator:
        for acct in page.get('Accounts'):
            yield account_details(client = org, child = acct)


if __name__ == "__main__":

    logger = logging.getLogger(__name__)
    logger.critical("Not a standalone script.")
    sys.exit(1)
