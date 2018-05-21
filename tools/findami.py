# -*- coding: utf-8 -*-
"""
The CLI program "findami"
"""
import logging
import boto3
from botocore.exceptions import ClientError
from utilities.utils import print_progress
from utilities.utils import get_regions
from utilities.utils import dict_from_tuple

def get_ami_allregions(ami_id, specific_region):
    """Returns a dictionary enriched with AWS information about images.
    Searches every AWS region hosting the EC2 service.

    Arguments:
        ami_dict {String} -- Key is the amiID.
        Value is the result of describe_images()
    """
    logger = logging.getLogger(__name__)
    ami_dict = dict_from_tuple(ami_id)
    logger.debug('Search regions %s', specific_region)
    n = -1
    for region in get_regions('ec2'):
        n = n + 1
        logger.debug(str('Attempting region {} ').format(region))
        if (specific_region and specific_region is region) or not specific_region:
            ans = get_ami_info(ami_dict, region, n)

    #print_progress(15, 15, '', 'Finished', 1)
    return ami_dict


def get_ami_info(ami_dict, region, n=0):
    """For a specific region, search for ami descriptions
    for each amiid in a dictionary

    Arguments:
        ami_dict {[type]} -- [description]
        region {[type]} -- [description]

    Keyword Arguments:
        n {number} -- current iteration (default: {0})
    """
    logger = logging.getLogger(__name__)
    ec2_client = boto3.client('ec2', region_name=region)
    for ami_id in ami_dict:

        #print_progress(n, 15, str(region), str(ami_id), 1)

        if not ami_dict[ami_id]:
            logger.debug(str('Searching for {} in {}').format(ami_id, region))
            try:
                ami_info = ec2_client.describe_images(
                    ImageIds=[ami_id])['Images'][0]
                ami_info['Region'] = region
                ami_dict[ami_id] = ami_info
                logger.log(logging.INFO, str(
                    'Found {} [{}]').format(ami_id, ami_info))
            except ClientError as e:
                logger.log(logging.DEBUG, e.response)
                #print("Error: {} in {}".format(e.message, region))
            except IndexError:
                return {}
