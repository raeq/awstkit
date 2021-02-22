import ipaddress
import logging
from collections import defaultdict
from pprint import pprint

import boto3
import netaddr

from . import utils


def _get_vpc_data(session: boto3.session, region="", vpc="") -> dict:
    logger = logging.getLogger(__name__)
    ips: defaultdict = defaultdict(dict)
    vpcs: defaultdict = defaultdict(dict)
    instances: defaultdict = defaultdict(dict)

    for reg in utils.get_regions("ec2"):
        if (region and region == reg) or not region:

            client = session.client('ec2', region_name=reg)

            response_iterator = None
            try:
                response_iterator = client.get_paginator(
                        "describe_instances").paginate()

                for page in response_iterator:
                    for r in page.get("Reservations"):
                        for i in r.get("Instances"):
                            instances[i.get("InstanceId")] = i
                            if i.get("PublicIpAddress"):
                                ips[i["PublicIpAddress"]] = i
                            if i.get("PrivateIpAddress"):
                                ips[i["PrivateIpAddress"]] = i
            except Exception as e:
                logger.warning(f"Failed to describe_instances in region {region} {e}")

            response_iterator = None
            try:
                response_iterator = client.get_paginator(
                        "describe_instances").paginate()
                for page in response_iterator:
                    for i in page.get("Addresses"):
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

                for page in response_iterator:
                    for i in page["NetworkInterfaces"]:
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

                for page in response_iterator:
                    for v in page["Vpcs"]:

                        if (vpc and vpc == v["VpcId"]) or not vpc:

                            vpcs[v["VpcId"]]["metadata"] = v
                            vpcs[v["VpcId"]]["region"] = reg

                            # get IGWs
                            response_iterator_igw = client.get_paginator(
                                    "describe_internet_gateways").paginate(Filters=[
                                {
                                    'Name': 'attachment.vpc-id',
                                    'Values': [
                                        v["VpcId"],
                                    ],
                                },
                            ],
                            )
                            for page in response_iterator_igw:
                                vpcs[v["VpcId"]]["igws"] = page.get("InternetGateways")

                            # get rts

                            response_iterator_rts = client.get_paginator(
                                    "describe_route_tables").paginate(Filters=[
                                {
                                    'Name': 'vpc-id',
                                    'Values': [
                                        v["VpcId"],
                                    ],
                                },
                            ],
                            )
                            for page in response_iterator_rts:
                                vpcs[v["VpcId"]]["rts"] = page.get("RouteTables")

                            # get acls

                            response_iterator_acl = client.get_paginator(
                                    "describe_network_acls").paginate(Filters=[
                                {
                                    'Name': 'vpc-id',
                                    'Values': [
                                        v["VpcId"],
                                    ],
                                },
                            ],
                            )
                            for page in response_iterator_acl:
                                vpcs[v["VpcId"]]["acl"] = page.get("NetworkAcls")

                            # get subnets
                            response_iterator_subs = client.get_paginator(
                                    "describe_subnets").paginate(Filters=[
                                {
                                    'Name': 'vpc-id',
                                    'Values': [
                                        v["VpcId"],
                                    ],
                                },
                            ],
                            )
                            for page in response_iterator_subs:
                                vpcs[v["VpcId"]]["subnets"] = page.get("Subnets")

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
        errors.append(f"The searched for IP address {dst_ip} was not found in your account.")
        return errors, []
    else:
        target_eni = public_ips.get(dst).get('NetworkInterfaceId')
        if public_ips.get(dst).get("Status") == "in-use":
            successes.append(f"The searched for IP address {dst_ip} is in use and "
                             f"{target_eni} is attached.")
        else:
            errors.append(f"The searched for IP address {dst_ip} was found but {target_eni} "
                          f"is not attached.")

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
                        successes.append(f"There is an attached and available IGW "
                                         f"{i.get('InternetGatewayId')} for vpc {a.get('VpcId')}")
                        break

        if not target_igw:
            errors.append(f"There are no IGWs attached and available for this VPC")

        # TODO do we have a VPN GW?

        # TODO: do we have an virtual gateway?

        # TODO: do we have VPC Peering?

        # TODO: do we have a transit gateway?

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
        igw_routed: str = None
        for route_table in target_vpc.get("rts"):
            if route_table.get("VpcId") == target_vpc_id:
                for route in route_table.get("Routes"):
                    if route.get("GatewayId") == target_igw.get('InternetGatewayId'):
                        if route.get('State') == "active":
                            igw_routed = f"The main route table has a route to the " \
                                         f"IGW {target_igw.get('InternetGatewayId')}"
                            successes.append(igw_routed)

                            # is the route applicable to the src?
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(route.get('DestinationCidrBlock')):
                                successes.append(
                                        f"The route table entry to the GW {target_igw.get('InternetGatewayId')} "
                                        f"has a valid destination "
                                        f"({route.get('DestinationCidrBlock')}) to src {src}")
                            else:
                                errors.append(f"The route table entry to the GW {target_igw.get('InternetGatewayId')} "
                                              f"does not have a valid destination "
                                              f"({route.get('DestinationCidrBlock')}) to src {src}")

                if not igw_routed:
                    errors.append(f"The main route table {route_table.get('RouteTableId')} is not routed through "
                                  f"{target_igw.get('InternetGatewayId')}")

        # are we being blocked by ACLs?
        target_acl_assoc = None
        for acl in target_vpc.get("acl"):
            ingress_msg: str = ""
            egress_msg: str = ""

            for acl_association in acl.get("Associations"):
                if acl_association.get("SubnetId") == target_subnet.get("SubnetId"):
                    target_acl_assoc = acl

                    for entry in acl.get("Entries"):
                        if entry.get("Egress") == False:
                            # ingress rule
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(entry.get("CidrBlock")):
                                if entry.get("RuleAction") == "allow":
                                    successes.append(f"Ingress rule #{entry.get('RuleNumber')} allows ingress from "
                                                     f"{entry.get('CidrBlock')} "
                                                     f"using protocol {entry.get('Protocol')} "
                                                     f"in {acl.get('NetworkAclId')}")
                                    ingress_msg = True
                                else:
                                    if not ingress_msg:
                                        errors.append(
                                                f"Ingress rule #{entry.get('RuleNumber')} denies ingress from {src}"
                                                f" in {acl.get('NetworkAclId')}")
                        else:
                            # egress rule
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(entry.get("CidrBlock")):
                                if entry.get("RuleAction") == "allow":
                                    successes.append(f"Egress rule #{entry.get('RuleNumber')} allows egress to "
                                                     f"{entry.get('CidrBlock')} "
                                                     f"using protocol {entry.get('Protocol')} "
                                                     f" in {acl.get('NetworkAclId')}")
                                    egress_msg = True
                                else:
                                    if not egress_msg:
                                        errors.append(f"Egress rule #{entry.get('RuleNumber')} denies egress to {src}"
                                                      f" in {acl.get('NetworkAclId')}")

                    if not ingress_msg:
                        errors.append(f"No explicit ingress allow found in {acl.get('NetworkAclId')}")
                    if not egress_msg:
                        errors.append(f"No explicit egress allow found in {acl.get('NetworkAclId')}")

        # are we being blocked by security groups?
        if target_eni:
            # get the ip address dictionary
            my_ip: dict = public_ips.get(dst)
            groups: dict = my_ip.get("Groups")

            # get the Groups
            sg_ingress_msg: str = None
            sg_egress_msg: str = None

            for group in groups:
                reg = utils.region_from_az(
                        public_ips[dst].get("AvailabilityZone"))
                client = session.client('ec2', region_name=reg)

                group_name = group.get("GroupId")
                response = client.describe_security_groups(
                        GroupIds=[group_name]
                )

                group_data = response['SecurityGroups'][0]

                # Iterate rules
                for rule in group_data.get("IpPermissions"):
                    for ip_range in rule.get("IpRanges"):
                        if netaddr.IPAddress(src) in netaddr.IPNetwork(ip_range.get('CidrIp')):
                            sg_ingress_msg = f"Security group {group_data.get('GroupId')} \"" \
                                             f"{group_data.get('GroupName')}\" " \
                                             f"allows {src} " \
                                             f"ingress to {dst} in {ip_range.get('CidrIp')} using " \
                                             f"protocol {rule.get('IpProtocol')} "

                for rule in group_data.get("IpPermissionsEgress"):
                    for ip_range in rule.get("IpRanges"):
                        if netaddr.IPAddress(dst) in netaddr.IPNetwork(ip_range.get('CidrIp')):
                            sg_egress_msg = f"Security group {group_data.get('GroupId')} \"" \
                                            f"{group_data.get('GroupName')}\" " \
                                            f"allows {dst} " \
                                            f"egress to {src} in {ip_range.get('CidrIp')} using " \
                                            f"protocol {rule.get('IpProtocol')} "

                """
                {'Description': 'default VPC security group', 'GroupName': 'default', 'IpPermissions': [], 'OwnerId': 
                '287687199621', 'GroupId': 'sg-0c539e6d394ec7dd8', 'IpPermissionsEgress': [{'IpProtocol': '-1', 
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [
                ]}], 'VpcId': 'vpc-0ef2f414da7392532'}
                """
                # look for a specific allow rule. There are no denies in security groups.

                # if we don't yet have a positive outcome
                # if we have a prefixlistid, get the CIDRs in the prefix list and iterate
                # get_managed_prefix_list_entries PrefixListId='string'

                # TODO: Is the searched for IP address in a PrefixList?

            if sg_ingress_msg:
                successes.append(sg_ingress_msg)
            else:
                errors.append(f"No security group ingress rule found from source {src}.")
            if sg_egress_msg:
                successes.append(sg_egress_msg)
            else:
                errors.append(f"No security group egress rule found to destination {dst}.")

        # is the port open?

    # TODO check for Network Firewalls

    return errors, successes
