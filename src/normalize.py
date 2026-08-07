"""Normalize AWS Security Group and Azure NSG exports into one common format.

AWS and Azure describe network rules differently. This module flattens both into
a single list of rule records so the rest of the analysis doesn't need to care
which platform a rule came from.

One record = one permitted path: one source, one port range, one direction.
A single AWS permission block covering both an IPv4 and an IPv6 range produces
two records, because those are two separately configured permissions.

Input formats:
    AWS    aws ec2 describe-security-groups --output json
    Azure  az network nsg list --output json
"""

import json

ALL_PORTS = (0, 65535)


def parse_port_range(value):
    """Return (from_port, to_port) for an Azure port range string.

    Azure writes ports as "22", "8000-8090", or "*" for everything.
    """
    if value in ("*", "", None):
        return ALL_PORTS
    if "-" in str(value):
        low, high = str(value).split("-", 1)
        return int(low), int(high)
    port = int(value)
    return port, port


def format_ports(from_port, to_port, protocol):
    """Human-readable port label for a finding row."""
    if protocol in ("-1", "*", "all"):
        return "All traffic"
    if (from_port, to_port) == ALL_PORTS:
        return f"{protocol.upper()} 0-65535"
    if from_port == to_port:
        return f"{protocol.upper()} {from_port}"
    return f"{protocol.upper()} {from_port}-{to_port}"


def _record(**kwargs):
    """Build a rule record with every field present, so downstream code can
    rely on the keys existing."""
    base = {
        "platform": "",
        "account": "",
        "group_id": "",
        "group_name": "",
        "direction": "",
        "protocol": "",
        "from_port": 0,
        "to_port": 65535,
        "port_label": "",
        "source": "",
        "destination": "",
        "rule_name": "",
        "priority": None,
        "action": "Allow",
        "description": "",
        "ip_version": "IPv4",
    }
    base.update(kwargs)
    return base


# ----------------------------------------------------------------------
# AWS
# ----------------------------------------------------------------------

def _aws_permissions(group, block, direction):
    """Expand one AWS permission block into individual rule records."""
    protocol = block.get("IpProtocol", "-1")
    all_protocols = protocol == "-1"

    from_port = block.get("FromPort", 0)
    to_port = block.get("ToPort", 65535)
    if all_protocols:
        from_port, to_port = ALL_PORTS

    label = format_ports(from_port, to_port, protocol)

    common = {
        "platform": "AWS",
        "account": group.get("OwnerId", ""),
        "group_id": group.get("GroupId", ""),
        "group_name": group.get("GroupName", ""),
        "direction": direction,
        "protocol": "all" if all_protocols else protocol,
        "from_port": from_port,
        "to_port": to_port,
        "port_label": label,
    }

    peer_field = "destination" if direction == "Outbound" else "source"
    records = []

    for entry in block.get("IpRanges", []):
        records.append(_record(
            **common,
            **{peer_field: entry.get("CidrIp", "")},
            description=entry.get("Description", ""),
            ip_version="IPv4",
        ))

    for entry in block.get("Ipv6Ranges", []):
        records.append(_record(
            **common,
            **{peer_field: entry.get("CidrIpv6", "")},
            description=entry.get("Description", ""),
            ip_version="IPv6",
        ))

    for entry in block.get("UserIdGroupPairs", []):
        records.append(_record(
            **common,
            **{peer_field: entry.get("GroupId", "")},
            description=entry.get("Description", ""),
            ip_version="SecurityGroup",
        ))

    for entry in block.get("PrefixListIds", []):
        records.append(_record(
            **common,
            **{peer_field: entry.get("PrefixListId", "")},
            description=entry.get("Description", ""),
            ip_version="PrefixList",
        ))

    return records


def load_aws(path):
    """Read an AWS describe-security-groups export into rule records."""
    with open(path) as handle:
        data = json.load(handle)

    records = []
    for group in data.get("SecurityGroups", []):
        for block in group.get("IpPermissions", []):
            records.extend(_aws_permissions(group, block, "Inbound"))
        for block in group.get("IpPermissionsEgress", []):
            records.extend(_aws_permissions(group, block, "Outbound"))
    return records


# ----------------------------------------------------------------------
# Azure
# ----------------------------------------------------------------------

def _azure_values(rule, singular, plural):
    """Azure stores these as either a single string or a list. Return a list."""
    many = rule.get(plural) or []
    if many:
        return list(many)
    one = rule.get(singular)
    return [one] if one else ["*"]


def _subscription_from_id(resource_id):
    parts = str(resource_id).split("/")
    if "subscriptions" in parts:
        return parts[parts.index("subscriptions") + 1]
    return ""


def load_azure(path, include_defaults=False):
    """Read an az network nsg list export into rule records.

    Default security rules (priority 65000+) are excluded by default. They
    exist on every NSG and are not a configuration choice, so counting them
    as findings would inflate every result.
    """
    with open(path) as handle:
        data = json.load(handle)

    records = []
    for nsg in data:
        subscription = _subscription_from_id(nsg.get("id", ""))
        rules = list(nsg.get("securityRules") or [])
        if include_defaults:
            rules += list(nsg.get("defaultSecurityRules") or [])

        for rule in rules:
            protocol = rule.get("protocol", "*")
            direction = rule.get("direction", "Inbound")
            peer_field = "destination" if direction == "Outbound" else "source"

            if direction == "Outbound":
                peers = _azure_values(rule, "destinationAddressPrefix",
                                      "destinationAddressPrefixes")
            else:
                peers = _azure_values(rule, "sourceAddressPrefix",
                                      "sourceAddressPrefixes")

            ports = _azure_values(rule, "destinationPortRange",
                                  "destinationPortRanges")

            for peer in peers:
                for port in ports:
                    from_port, to_port = parse_port_range(port)
                    records.append(_record(
                        platform="Azure",
                        account=subscription,
                        group_id=nsg.get("id", ""),
                        group_name=nsg.get("name", ""),
                        direction=direction,
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        port_label=format_ports(from_port, to_port, protocol),
                        rule_name=rule.get("name", ""),
                        priority=rule.get("priority"),
                        action=rule.get("access", "Allow"),
                        description=rule.get("description", ""),
                        ip_version="IPv4",
                        **{peer_field: peer},
                    ))
    return records


if __name__ == "__main__":
    aws = load_aws("sample_data/aws_security_groups.json")
    azure = load_azure("sample_data/azure_nsgs.json")
    print(f"AWS records:   {len(aws)}")
    print(f"Azure records: {len(azure)}")
    for rule in aws + azure:
        peer = rule["destination"] if rule["direction"] == "Outbound" else rule["source"]
        print(f"  {rule['platform']:6} {rule['group_name']:18} "
              f"{rule['direction']:8} {rule['port_label']:15} {peer}")
