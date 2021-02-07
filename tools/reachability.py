import ipaddress
import logging
from collections import defaultdict
from pprint import pprint

import boto3

from . import utils


def _get_vpc_data(session: boto3.session, region="", vpc="") -> dict:
    logger = logging.getLogger(__name__)
    ips: defaultdict = defaultdict(dict)
    vpcs: defaultdict = defaultdict(dict)

    for reg in utils.get_regions("ec2"):
        if (region and region == reg) or not region:

            client = session.client('ec2', region_name=reg)

            response_iterator = None
            try:
                response_iterator = client.get_paginator(
                        "describe_instances").paginate()

                for p in response_iterator:
                    for r in p.get("Reservations"):
                        for i in r.get("Instances"):
                            if i.get("PublicIpAddress"):
                                ips[i["PublicIpAddress"]] = i
                            if i.get("PrivateIpAddress"):
                                ips[i["PrivateIpAddress"]] = i
            except Exception as e:
                logger.warning(f"Failed to describe_instances in region {region} {e}")

            response_iterator = None
            try:
                response = client.describe_addresses()["Addresses"]

                for i in response:
                    if i.get("PublicIp"):
                        ips[i["PublicIp"]] = i
                    if i.get("PrivateIpAddress"):
                        ips[i["PrivateIpAddress"]] = i
            except Exception as e:
                logger.warning(f"Failed to describe_addresses in region {region} {e}")

            response_iterator = None
            try:
                response_iterator = client.get_paginator(
                        "describe_network_interfaces").paginate()

                for p in response_iterator:
                    for i in p["NetworkInterfaces"]:
                        if i.get("Association"):
                            if i.get("Association").get("PublicIp"):
                                ips[i["Association"]["PublicIp"]] = i
                        for x in i.get('PrivateIpAddresses'):
                            ips[x.get('PrivateIpAddress')] = i
            except Exception as e:
                logger.warning(f"Failed to describe network_interfaces in region {region} {e}")

            response_iterator = None
            try:
                response_iterator = client.get_paginator(
                        "describe_vpcs").paginate()

                for p in response_iterator:
                    for v in p["Vpcs"]:

                        if (vpc and vpc == v["VpcId"]) or not vpc:

                            vpcs[v["VpcId"]]["metadata"] = v
                            vpcs[v["VpcId"]]["region"] = reg

                            # get IGWs
                            response_iterator_igw = client.get_paginator(
                                    "describe_internet_gateways").paginate()
                            for p in response_iterator_igw:
                                vpcs[v["VpcId"]]["igws"] = p["InternetGateways"]

                            # get rts
                            response_iterator_rts = client.get_paginator(
                                    "describe_route_tables").paginate()
                            for p in response_iterator_rts:
                                vpcs[v["VpcId"]]["rts"] = p["RouteTables"]

                            # get acls
                            response_iterator_acl = client.get_paginator(
                                    "describe_network_acls").paginate()
                            for p in response_iterator_acl:
                                vpcs[v["VpcId"]]["acl"] = p["NetworkAcls"]

                            # get subnets
                            response_iterator_subs = client.get_paginator(
                                    "describe_subnets").paginate()
                            for p in response_iterator_subs:
                                vpcs[v["VpcId"]]["subnets"] = p["Subnets"]

            except Exception as e:
                logger.warning(f"Failed to describe VPCs in region {region} {e}")

    return ips, vpcs


def is_reachable(vpc="", region="", profile="", src="", dst=""):
    logger = logging.getLogger(__name__)

    if not src or not dst:
        logger.info(f"Source or destination IP is empty src: '{src}' dst: '{dst}'")
        return False

    src_ip = ipaddress.ip_address(src)
    dst_ip = ipaddress.ip_address(dst)

    if (src_ip.is_loopback or src_ip.is_link_local) or (dst_ip.is_loopback or dst_ip.is_link_local):
        return False

    # here we need to get the CIDR of this VPC
    # VPC is a regional service. Each region can have 0:m VPCs

    session = boto3.session.Session(profile_name=profile)

    public_ips: dict
    vpcs: dict

    public_ips, vpcs = _get_vpc_data(session, region, vpc)
    pprint(public_ips)
    pprint(vpcs)

    errors: list = []
    successes: list = []
    target_eni = None

    # was the ip found?
    if dst not in public_ips:
        errors.append(f"The searched for IP address {dst_ip} was not found")
        return errors, []
    else:
        if public_ips.get(dst).get("Status") == "in-use":
            successes.append(f"The searched for IP address {dst_ip} is in use by "
                             f"eni {public_ips.get(dst).get('NetworkInterfaceId')}.")
            target_eni = public_ips.get(dst).get('NetworkInterfaceId')
        else:
            errors.append(f"The searched for IP address {dst_ip} was found but is not in use.")

    if src_ip.is_global and dst in public_ips:

        # is the searched for IP address in the given destination VPC?
        if vpc:
            if public_ips[dst].get("VpcId") == vpc:
                successes.append(f"The searched for IP address {dst_ip} exists in the given VPC {vpc}")
            else:
                errors.append(f"The searched for IP address {dst_ip} is not in the given VPC {vpc}, it is "
                              f"in {public_ips[dst].get('VpcId')}")
        else:
            successes.append(f"The searched for IP address {dst_ip} exists in the VPC {vpc}")

        # do we have an IGW for this VPC?
        target_vpc = vpcs[public_ips[dst].get("VpcId")]
        target_vpc_id = public_ips[dst].get("VpcId")
        target_igw = None
        target_subnet = None

        for i in target_vpc.get("igws"):
            for a in i.get("Attachments"):
                if a.get('VpcId') == target_vpc_id:
                    if a.get("State") == "available":
                        target_igw = i
                        successes.append(f"There is an attached and available IGW {i} for vpc {a.get('VpcId')}")
                        break

        if not target_igw:
            errors.append(f"There are no IGWs attached and available for this VPC")

        # is the VGW routed to the private IP address?
        my_subnet = public_ips[dst].get("SubnetId")
        for subnet in vpcs[target_vpc_id].get("subnets"):
            if subnet.get("SubnetId") == my_subnet:
                if subnet.get("State") == "available":
                    successes.append(f'The subnet used by the ip {dst} '
                                     f'has the range {subnet.get("CidrBlock")} '
                                     f'and has the state {subnet.get("State")} ')
                    target_subnet = subnet
                else:
                    errors.append(f'The subnet used by the ip {dst} '
                                  f'has the range {subnet.get("CidrBlock")} '
                                  f'and has the state {subnet.get("State")} ')

        for route_table in target_vpc.get("rts"):
            if route_table.get("VpcId") == target_vpc_id:
                for route in route_table.get("Routes"):
                    if route.get("GatewayId") == target_igw.get('InternetGatewayId'):
                        if route.get('State') == "active":
                            successes.append(f"The main route table has a route to the "
                                             f"IGW {target_igw.get('InternetGatewayId')} ")
                        else:
                            errors.append(f"The main route table {route_table.get('RouteTableId')} is blackholed")

        # are we being blocked by ACLs?

        # are we being blocked by security groups?
        if target_eni:
            pass

        # is the port open?

    if src_ip.is_global or dst_ip.is_global:
        # here we need to check for traffic exiting the VPC
        pass

    return errors, successes
