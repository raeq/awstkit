# -*- coding: utf-8 -*-
"""
Common util methods
"""
import boto3
import sys


def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=40):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    pbar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' %
                     (prefix, pbar, percents, '%', suffix)),

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()


def get_regions(service='ec2'):
    return boto3.session.Session().get_available_regions(service)


def region_from_az(az: str = "") -> str:
    """

    :param az: us-east-1b
    :type az: us-east1
    :return:
    :rtype:
    """
    if not az:
        return ""

    parts = az.split("-")
    ret_val = parts[0] + "-" + parts[1] + "-" + parts[2][:-1]
    return ret_val


def dict_from_tuple(tuples):
    adict = {}
    for item in tuples:
        adict[item] = ''
    return adict
