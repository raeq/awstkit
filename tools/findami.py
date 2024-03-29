#!/usr/bin/env python3
"""
The CLI program "findami"
"""

import logging

import boto3
from botocore.exceptions import ClientError

from . import utils


def get_ami_allregions(ami_id, specific_region, profile: str = ""):
    """Returns a dictionary enriched with AWS information about images.
    Searches every AWS region hosting the EC2 service.

    Arguments:
        ami_dict {String} -- Key is the amiID.
        Value is the result of describe_images()
    """
    logger = logging.getLogger(__name__)
    ami_dict = utils.dict_from_tuple(ami_id)
    logger.debug('Search regions %s', specific_region)
    n = -1
    for region in utils.get_regions('ec2'):
        n = n + 1
        logger.debug(str(f"Attempting region {region} "))
        if (specific_region and specific_region == region) or not specific_region:
            ami_dict = get_ami_info(ami_dict, region, profile, n)

    return ami_dict


def get_ami_info(amis, region, profile: str = "", n=0):
    """For a specific region, search for ami descriptions
    for each amiid in a dictionary

    Arguments:
        ami_dict {[type]} -- [description]
        region {[type]} -- [description]

    Keyword Arguments:
        n {number} -- current iteration (default: {0})
    """
    logger = logging.getLogger(__name__)
    session = boto3.session.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name=region)
    for ami_id in amis:

        if not amis[ami_id]:
            logger.debug(str(f"Searching for {ami_id} in {region}"))
            try:
                ami_info = ec2_client.describe_images(
                        ImageIds = [ami_id])['Images'][0]
                ami_info['Region'] = region
                amis[ami_id] = ami_info
                logger.log(logging.INFO, str(
                        'Found {} [{}]').format(ami_id, ami_info))
            except ClientError as e:
                logger.log(logging.DEBUG, e.response)
            except IndexError:
                return {}
    return amis
