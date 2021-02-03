# -*- coding: utf-8 -*-
"""
The CLI program "checkcerts"
"""
import logging
from pprint import pprint

import boto3

from . import utils


def _get_certs(specific_region):
    """_get_certs.

    Args:
        specific_region:
    """
    logger = logging.getLogger(__name__)

    certs = []
    available_regions = utils.get_regions("acm")

    if specific_region != "":
        if specific_region in available_regions:
            logger.debug(
                    f"Searching region {specific_region} in regions {available_regions}."
            )
            available_regions = [specific_region]
        else:
            logger.critical(
                    f"Invalid region supplied '{specific_region}' not in regions {available_regions}"
            )
            raise (RuntimeError)

    for region in available_regions:

        logger.debug(f"Searching '{region}' for certs.")
        client = boto3.client("acm", region_name=region)

        try:
            response_iterator = client.get_paginator(
                    "list_certificates").paginate()
        except Exception as e:
            logger.error("message")
        else:
            for p in response_iterator:
                for i in p["CertificateSummaryList"]:
                    c = client.describe_certificate(
                            CertificateArn=i["CertificateArn"])

                    certs.append(c)
    return certs


def _check_one_item(mycert):
    """Takes a certificate object, and performs validation checks."""
    logger = logging.getLogger(__name__)
    logger.debug(mycert["Certificate"]["Status"])
    logger.debug(mycert["Certificate"]["Options"]
                 ["CertificateTransparencyLoggingPreference"])

    if mycert["Certificate"]["Status"].upper() != "ISSUED":
        logger.info(
                "Cert %s is not issued (%s).",
                mycert["Certificate"]["CertificateArn"],
                mycert["Certificate"]["Status"],
        )
    elif (mycert["Certificate"]["Options"]
          ["CertificateTransparencyLoggingPreference"].lower() == "enabled"):
        logger.info(
                "Cert %s transparency logging (%s).",
                mycert["Certificate"]["CertificateArn"],
                mycert["Certificate"]["Status"],
        )
    else:
        logger.info(f"Cert '{mycert.url}' certificate transparency logging is"
                    f" disabled.")


def check_certs(specific_region):
    """check_certs.

    Args:
        specific_region:
    """
    cert_check_dict = dict()
    logger = logging.getLogger(__name__)

    logger.debug(f"Checking for certificates in region: {specific_region}")

    for cert in _get_certs(specific_region):
        pprint(cert)
        cert_check_dict[cert["Certificate"]["CertificateArn"]] = cert
        _check_one_item(cert)

    return cert_check_dict
