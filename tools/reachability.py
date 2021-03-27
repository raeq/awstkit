import ipaddress
import logging
from collections import defaultdict

import boto3
import netaddr

from . import utils


def _get_vpc_data(session: boto3.session,
                  region="",
                  vpc="") -> tuple[defaultdict, defaultdict]:
    """_get_vpc_data.

    Args:
        session (boto3.session): session
        region:
        vpc:

    Returns:
        tuple[defaultdict, defaultdict]:
    """
    logger = logging.getLogger(__name__)
    ips: defaultdict = defaultdict(dict)
    vpcs: defaultdict = defaultdict(dict)
    instances: defaultdict = defaultdict(dict)

    def get_page_item(method: str,
                      page_name: str,
                      item: str,
                      filters: list = None):
        """get_page_item.

        Args:
            method (str): method
            page_name (str): page_name
            item (str): item
            filters (list): filters
        """
        if not item:
            raise AttributeError()

        for page in get_page(method, page_name, filters):
            for i in page.get(item):
                yield i

    def get_page(method: str, page_name: str, filters: list = None):
        """get_page.

        Args:
            method (str): method
            page_name (str): page_name
            filters (list): filters
        """
        if not page_name:
            raise AttributeError()

        for page in get_ec2_paginator(method, filters):
            for r in page.get(page_name):
                yield r

    def get_ec2_paginator(method: str, filters: list = None):
        """get_ec2_paginator.

        Args:
            method (str): method
            filters (list): filters
        """
        if not method:
            raise AttributeError()
        if not filters:
            filters = []

        return ec2_client.get_paginator(method).paginate(Filters=filters)

    for reg in utils.get_regions("ec2"):
        if (region and region == reg) or not region:

            ec2_client = session.client("ec2", region_name=reg)

            try:
                for i in get_page_item("describe_instances", "Reservations",
                                       "Instances"):
                    instances[i.get("InstanceId")] = i
                    if i.get("PublicIpAddress"):
                        ips[i["PublicIpAddress"]] = i
                    if i.get("PrivateIpAddress"):
                        ips[i["PrivateIpAddress"]] = i

            except Exception as e:
                logger.exception(e)

            try:
                response_iterator_adr = ec2_client.describe_addresses()
                for i in response_iterator_adr.get("Addresses"):
                    if i.get("PublicIp"):
                        ips[i["PublicIp"]] = i
                    if i.get("PrivateIpAddress"):
                        ips[i["PrivateIpAddress"]] = i
            except Exception as e:
                logger.exception(e)

            try:

                for i in get_page("describe_network_interfaces",
                                  "NetworkInterfaces"):
                    if i.get("Association"):
                        if i.get("Association").get("PublicIp"):
                            ips[i["Association"]["PublicIp"]] = i
                    for x in i.get("PrivateIpAddresses"):
                        ips[x.get("PrivateIpAddress")] = i
            except Exception as e:
                logger.warning(
                        f"Failed to describe network_interfaces in region {region} {e}"
                )

            try:
                for v in get_page("describe_vpcs", "Vpcs"):
                    if (vpc and vpc == v["VpcId"]) or not vpc:

                        vpcs[v["VpcId"]]["metadata"] = v
                        vpcs[v["VpcId"]]["region"] = reg

                        # get IGWs
                        for igw_page in get_ec2_paginator(
                                "describe_internet_gateways",
                                filters=[
                                    {
                                        "Name": "attachment.vpc-id",
                                        "Values": [
                                            v["VpcId"],
                                        ],
                                    },
                                ],
                        ):
                            if vpcs[v["VpcId"]].get("igws"):
                                vpcs[v["VpcId"]]["igws"].append(
                                        igw_page.get("InternetGateways"))
                            else:
                                vpcs[v["VpcId"]]["igws"] = igw_page.get(
                                        "InternetGateways")

                        # get rts

                        for rts_page in get_ec2_paginator(
                                "describe_route_tables",
                                filters=[
                                    {
                                        "Name": "vpc-id",
                                        "Values": [
                                            v["VpcId"],
                                        ],
                                    },
                                ],
                        ):
                            if vpcs[v["VpcId"]].get("rts"):
                                vpcs[v["VpcId"]]["rts"].append(
                                        rts_page.get("RouteTables"))
                            else:
                                vpcs[v["VpcId"]]["rts"] = rts_page.get(
                                        "RouteTables")

                        # get acls
                        for acl_page in get_ec2_paginator(
                                method="describe_network_acls",
                                filters=[
                                    {
                                        "Name": "vpc-id",
                                        "Values": [
                                            v["VpcId"],
                                        ],
                                    },
                                ],
                        ):
                            if vpcs[v["VpcId"]].get("acl"):
                                vpcs[v["VpcId"]]["acl"].append(
                                        acl_page.get("NetworkAcls"))
                            else:
                                vpcs[v["VpcId"]]["acl"] = acl_page.get(
                                        "NetworkAcls")

                        # get subnets
                        for sbn_page in get_ec2_paginator(
                                method="describe_subnets",
                                filters=[
                                    {
                                        "Name": "vpc-id",
                                        "Values": [
                                            v["VpcId"],
                                        ],
                                    },
                                ],
                        ):
                            if vpcs[v["VpcId"]].get("subnets"):
                                vpcs[v["VpcId"]]["subnets"].append(
                                        sbn_page.get("Subnets"))
                            else:
                                vpcs[v["VpcId"]]["subnets"] = sbn_page.get(
                                        "Subnets")

            except Exception as e:
                logger.exception(e)
                logger.warning(
                        f"Failed to describe VPCs in region {region} {e}")

    return ips, vpcs


def is_reachable(vpc="", region="", profile="", src="", dst=""):
    """is_reachable.

    Args:
        vpc:
        region:
        profile:
        src:
        dst:
    """
    logger = logging.getLogger(__name__)

    if not src or not dst:
        logger.info(
                f"Source or destination IP is empty src: '{src}' dst: '{dst}'")
        return False

    src_ip = ipaddress.ip_address(src)
    dst_ip = ipaddress.ip_address(dst)

    if (src_ip.is_loopback or src_ip.is_link_local) or (dst_ip.is_loopback or
                                                        dst_ip.is_link_local):
        return False

    # here we need to get the CIDR of this VPC
    # VPC is a regional service. Each region can have 0:m VPCs

    session = boto3.session.Session(profile_name=profile)

    public_ips: dict
    vpcs: dict

    public_ips, vpcs = _get_vpc_data(session, region, vpc)
    logger.debug(public_ips)
    logger.debug(vpcs)

    errors: list = []
    successes: list = []

    # was the ip found?
    if dst not in public_ips:
        errors.append(
                f"The searched for IP address {dst_ip} was not found in your account."
        )
        return errors, []

    target_eni = public_ips.get(dst).get("NetworkInterfaceId")
    if public_ips.get(dst).get("Status") == "in-use":
        successes.append(
                f"The searched for IP address {dst_ip} in AZ {public_ips.get(dst).get('AvailabilityZone')} is in "
                f"use "
                f"and "
                f"{target_eni} is attached.")
    else:
        errors.append(
                f"The searched for IP address {dst_ip} was found but {target_eni} in AZ "
                f"{public_ips.get(dst).get('AvailabilityZone')} "
                f"is not attached.")

    if src_ip.is_global and dst in public_ips:

        # is the searched for IP address in the given destination VPC?
        if vpc:
            if public_ips[dst].get("VpcId") == vpc:
                successes.append(
                        f"The searched for IP address {dst_ip} exists in the given VPC {vpc}"
                )
            else:
                errors.append(
                        f"The searched for IP address {dst_ip} is not in the given VPC {vpc}, it is "
                        f"in {public_ips[dst].get('VpcId')}")
        else:
            successes.append(
                    f"The searched for IP address {dst_ip} exists in the VPC {vpc}"
            )

        # do we have an IGW for this VPC?
        target_vpc: dict = vpcs[public_ips[dst].get("VpcId")]
        target_vpc_id: str = public_ips[dst].get("VpcId")
        target_igw: dict = {}
        target_subnet: dict = {}

        msg = f"The target {target_vpc_id} is in state {target_vpc.get('metadata').get('State')}"
        if target_vpc.get("metadata").get("State") == "available":
            successes.append(msg)
        else:
            errors.append(msg)

        for i in target_vpc.get("igws"):
            for a in i.get("Attachments"):
                if a.get("VpcId") == target_vpc_id:
                    if a.get("State") == "available":
                        target_igw = i
                        successes.append(
                                f"There is an attached and available IGW "
                                f"{i.get('InternetGatewayId')} for vpc {a.get('VpcId')}"
                        )
                        break

        if not target_igw:
            errors.append(
                    f"There are no IGWs attached and available for this VPC {target_vpc_id}"
            )

        # TODO do we have a VPN GW?

        # TODO: do we have a virtual gateway?

        # TODO: do we have VPC Peering?

        # TODO: do we have a transit gateway?

        # is the VGW routed to the private IP address?
        my_subnet = public_ips[dst].get("SubnetId")
        for subnet in vpcs[target_vpc_id].get("subnets"):
            if subnet.get("SubnetId") == my_subnet:
                if subnet.get("State") == "available":
                    successes.append(
                            f"The subnet used by the ip {dst} "
                            f'has the range {subnet.get("CidrBlock")} '
                            f'and has the state {subnet.get("State")} ')
                    target_subnet = subnet
                else:
                    errors.append(f"The subnet used by the ip {dst} "
                                  f'has the range {subnet.get("CidrBlock")} '
                                  f'and has the state {subnet.get("State")} ')
        igw_routed: str = ""
        for route_table in target_vpc.get("rts"):
            if route_table.get("VpcId") == target_vpc_id:
                for route in route_table.get("Routes"):
                    if route.get("GatewayId") == target_igw.get(
                            "InternetGatewayId"):
                        if route.get("State") == "active":
                            igw_routed = (
                                f"The main route table has a route to the "
                                f"IGW {target_igw.get('InternetGatewayId')}")
                            successes.append(igw_routed)

                            # is the route applicable to the src?
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(
                                    route.get("DestinationCidrBlock")):
                                successes.append(
                                        f"The route table entry to the GW {target_igw.get('InternetGatewayId')} "
                                        f"has a valid destination "
                                        f"({route.get('DestinationCidrBlock')}) to src {src}"
                                )
                            else:
                                errors.append(
                                        f"The route table entry to the GW {target_igw.get('InternetGatewayId')} "
                                        f"does not have a valid destination "
                                        f"({route.get('DestinationCidrBlock')}) to src {src}"
                                )

                if not igw_routed:
                    errors.append(
                            f"The main route table {route_table.get('RouteTableId')} is not routed through "
                            f"{target_igw.get('InternetGatewayId')}")

        # are we being blocked by ACLs?
        for acl in target_vpc.get("acl"):
            ingress_msg: str = ""
            egress_msg: str = ""

            for acl_association in acl.get("Associations"):
                if acl_association.get("SubnetId") == target_subnet.get(
                        "SubnetId"):

                    for entry in acl.get("Entries"):
                        if not entry.get("Egress"):
                            # ingress rule
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(
                                    entry.get("CidrBlock")):
                                if entry.get("RuleAction") == "allow":
                                    successes.append(
                                            f"Ingress rule #{entry.get('RuleNumber')} allows ingress from "
                                            f"{entry.get('CidrBlock')} "
                                            f"using protocol {entry.get('Protocol')} "
                                            f"in {acl.get('NetworkAclId')}")
                                    ingress_msg = ""
                                else:
                                    if not ingress_msg:
                                        errors.append(
                                                f"Ingress rule #{entry.get('RuleNumber')} denies ingress from {src}"
                                                f" in {acl.get('NetworkAclId')}")
                        else:
                            # egress rule
                            if netaddr.IPAddress(src) in netaddr.IPNetwork(
                                    entry.get("CidrBlock")):
                                if entry.get("RuleAction") == "allow":
                                    successes.append(
                                            f"Egress rule #{entry.get('RuleNumber')} allows egress to "
                                            f"{entry.get('CidrBlock')} "
                                            f"using protocol {entry.get('Protocol')} "
                                            f" in {acl.get('NetworkAclId')}")
                                    egress_msg = ""
                                else:
                                    if not egress_msg:
                                        errors.append(
                                                f"Egress rule #{entry.get('RuleNumber')} denies egress to {src}"
                                                f" in {acl.get('NetworkAclId')}")

                    if not ingress_msg:
                        errors.append(
                                f"No explicit ingress allow found in {acl.get('NetworkAclId')}"
                        )
                    if not egress_msg:
                        errors.append(
                                f"No explicit egress allow found in {acl.get('NetworkAclId')}"
                        )

        # are we being blocked by security groups?
        if target_eni:
            # get the ip address dictionary
            my_ip: dict = public_ips.get(dst)
            groups: dict = my_ip.get("Groups")

            # get the Groups
            sg_ingress_msg: str = ""
            sg_egress_msg: str = ""

            for group in groups:
                reg = utils.region_from_az(
                        public_ips[dst].get("AvailabilityZone"))
                client = session.client("ec2", region_name=reg)

                group_name = group.get("GroupId")
                response = client.describe_security_groups(
                        GroupIds=[group_name])

                group_data = response["SecurityGroups"][0]

                # Iterate rules
                for rule in group_data.get("IpPermissions"):
                    for ip_range in rule.get("IpRanges"):
                        if netaddr.IPAddress(src) in netaddr.IPNetwork(
                                ip_range.get("CidrIp")):
                            sg_ingress_msg = (
                                f"Security group {group_data.get('GroupId')} \""
                                f"{group_data.get('GroupName')}\" "
                                f"allows {src} "
                                f"ingress to {dst} in {ip_range.get('CidrIp')} using "
                                f"protocol {rule.get('IpProtocol')} ")

                for rule in group_data.get("IpPermissionsEgress"):
                    for ip_range in rule.get("IpRanges"):
                        if netaddr.IPAddress(dst) in netaddr.IPNetwork(
                                ip_range.get("CidrIp")):
                            sg_egress_msg = (
                                f"Security group {group_data.get('GroupId')} \""
                                f"{group_data.get('GroupName')}\" "
                                f"allows {dst} "
                                f"egress to {src} in {ip_range.get('CidrIp')} using "
                                f"protocol {rule.get('IpProtocol')} ")

                # look for a specific allow rule. There are no denies in security groups.

                # if we don't yet have a positive outcome
                # if we have a prefixlistid, get the CIDRs in the prefix list and iterate
                # get_managed_prefix_list_entries PrefixListId='string'

                # TODO: Is the searched for IP address in a PrefixList?

            if sg_ingress_msg:
                successes.append(sg_ingress_msg)
            else:
                errors.append(
                        f"No security group ingress rule found from source {src}.")
            if sg_egress_msg:
                successes.append(sg_egress_msg)
            else:
                errors.append(
                        f"No security group egress rule found to destination {dst}."
                )

        # is the port open?

    # TODO check for Network Firewalls

    return {"errors": errors, "successes": successes}
