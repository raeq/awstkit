#!/usr/bin/env python3
"""
The CLI program "listaccounts"
"""
import logging
import pprint

import boto3

hierarchy: dict = dict()


def getaccts_for_ou(ouid) -> list:
    """getaccts_for_ou.

    Args:
        ouid:

    Returns:
        list:
    """
    return []


def get_ou_ids(parent_id, client) -> list:
    """get_ou_ids.

    Args:
        parent_id:
        client:
    """
    full_result = []

    paginator = client.get_paginator("list_children")
    iterator = paginator.paginate(ParentId=parent_id,
                                  ChildType="ORGANIZATIONAL_UNIT")

    for page in iterator:
        for ou in page["Children"]:
            # 1. Add entry
            # 2. Fetch children recursively

            temp = client.describe_organizational_unit(
                    OrganizationalUnitId=ou["Id"])["OrganizationalUnit"]

            full_result.append(temp)
            get_ou_ids(ou["Id"], client)

    return full_result


def list_all_accounts(profile: str = "") -> list:
    """
    Lists all accounts in an organization according to OU structure
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"Starting listaccounts cli method with profile '{profile}'.")

    session = boto3.session.Session(profile_name=profile)
    client = session.client("sts")
    org = session.client("organizations")

    root = org.list_roots()["Roots"][0]
    root_id = root["Id"]

    org_id = ""

    import re
    p = re.compile(r"o-\w*")
    m = p.search(root["Arn"])

    org_id = m.group(0)

    orgdescription = org.describe_organization(
            Id=org_id)["Organization"]

    temp_ous = get_ou_ids(parent_id=root_id, client=org)

    all_ous: list = list()
    all_ous.append(root)
    all_ous.extend(temp_ous)
    return all_ous


def _list_all_accounts(profile: str = "") -> list:
    """list_all_accounts.

    Args:
        profile (str): profile

    Returns:
        list:
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"Starting listaccounts cli method with profile '{profile}'.")

    session = boto3.session.Session(profile_name=profile)
    client = session.client("sts")
    org = session.client("organizations")

    root_id = org.list_roots()["Roots"][0]["Id"]
    hierarchy["root"] = root_id
    all_ous = get_ou_ids(parent_id=root_id, client=org)
    all_ous[root_id] = "root"

    paginator = org.get_paginator("list_accounts")
    page_iterator = paginator.paginate()

    pprint.pprint(all_ous)

    accounts: list = []

    for page in page_iterator:
        print(page)

        for acct in page["Accounts"]:
            id = acct["Id"]
            acct["Tags"] = org.list_tags_for_resource(ResourceId=id)["Tags"]
            acct["Tag Policy"] = org.describe_effective_policy(
                    PolicyType="TAG_POLICY", TargetId=id)["EffectivePolicy"]
            acct["Service Control Policy"] = org.list_policies_for_target(
                    Filter="SERVICE_CONTROL_POLICY", TargetId=id)["Policies"]

            acct["parentou"] = org.list_parents(ChildId=id)["Parents"][0]

            breakpoint()
            all_ous[acct["parentou"]["Id"]]["account"] = "a"

            accounts.append(acct)

        pprint.pprint(all_ous)

    return accounts


if __name__ == "__main__":
    pprint.pprint(ou_id_list)

    logger = logging.getLogger(__name__)
    logger.critical("Not a standalone script.")
    exit(1)
