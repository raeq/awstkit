"""
The CLI program "kmskeys"
"""
import logging
from collections import defaultdict

import boto3

from tools.utils import get_regions


def get_keys(profile: str = "", region: str = ""):
    """
    Lists all keys in an account by region
    """
    keys: dict = defaultdict(dict)

    logger = logging.getLogger(__name__)
    logger.debug(f"Starting getkeys cli method with profile '{profile}' and region: '{region}'.")

    session = boto3.session.Session(profile_name=profile)
    kms = session.client("kms")

    for r in get_regions('kms'):

        logger.debug(str(f"Attempting region {r} "))
        if (region and region is r) or not region:
            client = session.client("kms", region_name=r)

            try:
                response_iterator = client.get_paginator(
                        "list_keys").paginate()
                for r in response_iterator:
                    for i in r["Keys"]:
                        kid = i["KeyId"]
                        keys[i["KeyId"]]["key"] = client.describe_key(KeyId=kid).get("KeyMetadata")
                        keys[i["KeyId"]]["aliases"] = client.list_aliases(KeyId=kid).get("Aliases")
                        keys[i["KeyId"]]["rotation_enabled"] = client.get_key_rotation_status(KeyId=kid).get(
                            "KeyRotationEnabled")
                        keys[i["KeyId"]]["tags"] = client.list_resource_tags(KeyId=kid).get("Tags")
                        keys[i["KeyId"]]["policies"] = client.list_key_policies(KeyId=kid).get("PolicyNames")
                        keys[i["KeyId"]]["grants"] = client.list_grants(KeyId=kid).get("Grants")
            except Exception as e:
                logger.warning(e)

    return keys
