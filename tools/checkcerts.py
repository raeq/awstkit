# -*- coding: utf-8 -*-
"""
The CLI program "checkcerts"
"""
import logging
import boto3
from pprint import pprint
from utilities.utils import get_regions
from utilities.utils import dict_from_tuple

def _get_certs(specific_region):
    logger = logging.getLogger(__name__)

    certs = []

    for region in get_regions('acm'):
        if (specific_region and specific_region is region) or not specific_region:
            logger.debug('Searching %s for certs.',region)
            client = boto3.client('acm', region_name=region)

            response_iterator = client.get_paginator(
                'list_certificates').paginate()

            for p in response_iterator:
                for i in p['CertificateSummaryList']:
                    c = client.describe_certificate(
                        CertificateArn=i['CertificateArn'])

                    certs.append(c)

    return certs


def _check_one_item(mycert):
    """Takes a certificate object, and performs validation checks."""
    logger = logging.getLogger(__name__)
    logger.debug(mycert['Certificate']['Status'])
    logger.debug(mycert['Certificate']['Options']['CertificateTransparencyLoggingPreference'])

    return

    if mycert['Certificate']['Status'].upper() != 'ISSUED':
        logger.warn("Cert %s is not issued (%s).", mycert['Certificate']['CertificateArn'], mycert['Certificate']['Status'])
    elif mycert['Certificate']['Options']['CertificateTransparencyLoggingPreference'].lower() == 'enabled':
        logger.warn("Cert %s transparency logging (%s).", mycert['Certificate']['CertificateArn'], mycert['Certificate']['Status'])
        # mycert.disable_transparency_logging()
    else:
        logger.info(
            "Cert %s certificate transparency logging is disabled.", mycert.url)
        # mycert.enable_transparency_logging()


def check_certs(specific_region):
    cert_check_dict = dict()
    logger = logging.getLogger(__name__)

    for cert in _get_certs(specific_region):
        pprint(cert)
        cert_check_dict[cert['Certificate']['CertificateArn']] = cert
        _check_one_item(cert)


    return cert_check_dict
