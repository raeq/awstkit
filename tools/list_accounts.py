#!/usr/bin/env python3
"""
The CLI program "listaccounts"
"""
import logging
import re
import sys

import boto3
from botocore.exceptions import ClientError

hierarchy: dict = dict()


def get_ou_ids(parent_id, client, full_result=None) -> list:
    """get_ou_ids.

    Args:
        parent_id:
        client:
    """
    if full_result is None:
        full_result = []

    paginator = client.get_paginator("list_children")
    iterator = paginator.paginate(ParentId=parent_id,
                                  ChildType="ORGANIZATIONAL_UNIT")

    for page in iterator:
        for ou in page["Children"]:
            # 1. Add entry
            # 2. Fetch children recursively

            temp: dict = client.describe_organizational_unit(
                    OrganizationalUnitId=ou["Id"])["OrganizationalUnit"]

            # get child accounts list_children
            children = client.list_accounts_for_parent(
                    ParentId=ou["Id"])["Accounts"]

            for child in children:
                if "Accounts" not in temp.keys():
                    temp["Accounts"] = []
                temp["Accounts"].append(child)

            full_result.append(temp)
            get_ou_ids(ou["Id"], client, full_result)

        # get the node from full_result where we currently are
        for node in full_result[::-1]:
            if node["Id"] == parent_id:

                paginator2 = client.get_paginator("list_accounts_for_parent")
                iterator2 = paginator2.paginate(ParentId=parent_id)

                for page2 in iterator2:
                    for child in page2["Accounts"]:
                        if "Accounts" not in full_result[0].keys():
                            node["Accounts"] = []

                        cid: str = child["Id"]
                        child["Tags"] = client.list_tags_for_resource(
                                ResourceId=cid)["Tags"]
                        child["TagPolicy"] = client.describe_effective_policy(
                                PolicyType="TAG_POLICY",
                                TargetId=cid)["EffectivePolicy"]
                        child[
                            "ServiceControlPolicy"] = client.list_policies_for_target(
                                Filter="SERVICE_CONTROL_POLICY",
                                TargetId=cid)["Policies"]
                        try:
                            child[
                                "DelegatedServices"] = client.list_delegated_services_for_account(
                                    AccountId=cid)["DelegatedServices"]
                        except ClientError as e:
                            if e.response["Error"][
                                "Code"] == "AccountNotRegisteredException":
                                child["DelegatedServices"] = []

                        node["Accounts"].append(child)

                break

    return full_result


def list_all_accounts(profile: str = "") -> list:
    """
    Lists all accounts in an organization according to OU structure
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"Starting listaccounts cli method with profile '{profile}'.")

    session = boto3.session.Session(profile_name=profile)
    org = session.client("organizations")

    root = org.list_roots()["Roots"][0]
    root_id = root["Id"]

    org_id = ""

    p = re.compile(r"o-\w*")
    m = p.search(root["Arn"])

    org_id = m.group(0)

    org_description = org.describe_organization(Id=org_id)["Organization"]

    all_ous: list = get_ou_ids(parent_id=root_id,
                               client=org,
                               full_result=[root])
    all_ous[0]["Description"] = org_description

    return all_ous


if __name__ == "__main__":

    logger = logging.getLogger(__name__)
    logger.critical("Not a standalone script.")
    sys.exit(1)
