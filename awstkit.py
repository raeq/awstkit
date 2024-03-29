#!/usr/bin/env python3
"""
CLI tool for getting information about instances and amis.
"""

import logging.config
from os import path
from pprint import pprint

import click
from botocore import exceptions as be

from tools.checkcerts import check_certs
from tools.config_aggregator_resources import get_resources
from tools.findami import get_ami_allregions
from tools.kms_keys import get_keys
from tools.list_accounts import list_all_accounts
from tools.reachability import is_reachable


LOGCONFIG = "logging_config.ini"


def log_path():
    """Gets the OS and environment independent path to the
    logger configuration file."""
    log_file_path = path.join(path.dirname(path.abspath(__file__)), LOGCONFIG)
    return log_file_path


logging.config.fileConfig(log_path(), disable_existing_loggers = True)
logger = logging.getLogger(__name__)

__version__ = "0.0.0"


@click.group()
@click.version_option(__version__, "-V", message = "%(version)s")
def cli():
    """cli.
    """
    logger.debug(f"Application startup.")


@cli.command()
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
def listaccounts(profile: str):
    """Lists all accounts in an Organization.
    """

    logger.debug(f"Begin listing accounts using profile {profile}")

    try:
        for k, v in enumerate(list_all_accounts(profile)):
            print(f'{k}\t{v}')
    except be.NoCredentialsError as e:
        logger.critical("No credentials found.", exc_info = True)
    except be.BotoCoreError as e:
        logger.exception(e)
    finally:
        logger.debug("End listing accounts")


@cli.command()
@click.option("--region", "-r", default = "", help = "single region to query")
@click.option("--allregions", "-a", is_flag = True, help = "query all ec2 regions")
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
@click.option(
        "--expired/--notexpired",
        "-x/-nx",
        default = False,
        help = "Expired to include \
    expired certs. Not expired to include only unexpired certs. If missing: all \
    expiry states are included",
)
@click.option(
        "--pending/--notpending",
        default = False,
        help = "Pending to include \
    certs pending validation. Not pending to include only non-pending certs. If missing: all \
    pending states are included",
)
def checkcerts(region, allregions, expired, pending, profile: str):
    """Checks all ACM Certificates in a region or globally.
    Optionally identifies certificates with 
    *Certificate Transparency Logging Enabled
    *Pending Validation
    *Expired

    
    Arguments:
        region {[type]} -- [description]
        allregions {[type]} -- [description]
    """

    logger.debug(f"Begin search for certs using profile {profile}")
    try:
        print(check_certs(region, profile))
    except be.NoCredentialsError as e:
        logger.critical("No credentials found.", exc_info = True)
    except Exception as e:
        logger.critical("Unexpected exception.", exc_info = True)
    finally:
        logger.debug("End search for certs")


@cli.command()
@click.argument("ami_id", nargs = -1, required = True)
@click.option("--region", "-r", default = "", help = "Restrict search to this single region")
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
def findami(ami_id, region, profile: str):
    """Finds information about AMIs, given a list of ids.

    Decorators:
        cli.command
        click.argument
        click.option
        click.option

    Arguments:
        ami_id {[string]} -- A list of ami IDs.
        region {String} -- The single region to search.
        allregions {Flag} -- Set this flag if all regions are to be searched.
    """

    logger.debug(f"Begin search for AMI {ami_id} using profile {profile}")
    try:
        pprint(get_ami_allregions(ami_id, region, profile))
    except be.NoCredentialsError as e:
        logger.critical("No credentials found.", exc_info = True)
    finally:
        logger.debug(f"End search for AMI {ami_id}")


@cli.command()
@click.option("--region", "-r", default = "", help = "Restrict search to this single region")
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
def getkeys(region: str, profile: str):
    """Finds information about KMS keys.
    """
    k = get_keys(region = region, profile = profile)
    pprint(k)


@cli.command()
@click.option("--region", "-r", default = "", help = "Restrict search to this single region")
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
@click.option("--vpc_destination", "-vd", default = "", help = "Restrict search to this specific destination vpc")
@click.option("--source", "-s", default = "", help = "The source IP address")
@click.option("--destination", "-d", default = "", help = "The destination IP address")
def reachability(vpc_destination: str, region: str, profile: str, source, destination):
    """Tests the reachability of IP addresses.
    """
    r = is_reachable(vpc = vpc_destination, region = region, profile = profile, src = source, dst = destination, )
    pprint(r)


@cli.command()
@click.option("--profile", "-p", required = False, default = "default", help =
"The awscli configuration profile for the master account.")
@click.option("--resource_type", "-rt", default = "", help = "Restrict search to this specific resource type.")
@click.option("--aggregator", "-ag", default = "", help = "Use this AWS Config Aggregator name.")
def aggregate_resources(resource_type: str, profile: str, aggregator: str):
    """Returns the resources in the chosen config resource aggregator.
    """

    for k, v in enumerate(get_resources(profile = profile, resource_type = resource_type,
                                        aggregator = aggregator)):
        d: list = list(dict(v).values())
        print(k, " ".join(d))


if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        logger.exception(e)
        raise RuntimeError from e
