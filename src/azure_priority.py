"""Classify Azure NSG rules as effective, redundant, or shadowed.

Azure evaluates NSG rules in priority order, lowest number first, and stops at
the first rule matching the traffic. A rule can therefore be present, look
significant, and decide nothing at all.

    effective   no earlier rule matches this traffic -- this rule decides
    redundant   an earlier Allow already permits it
    shadowed    an earlier Deny already blocks it

Getting this wrong in either direction distorts the results. Treating every
Allow rule as effective over-reports exposure that an earlier rule already
accounts for. Ignoring priority entirely means the finding gets written against
the wrong rule, and remediating that rule changes nothing.

AWS Security Groups have no priority and no Deny, so every AWS rule is
effective by definition.

Azure default rules live at priority 65000+, above the 4096 maximum for custom
rules, so they can never shadow a configured rule and are not considered here.
"""

import ipaddress

# Values meaning "anywhere, any IP version".
ANY_SOURCE = {"*", "any"}

# Values meaning "anywhere within one IP version".
ANY_V4 = "0.0.0.0/0"
ANY_V6 = "::/0"

# Ranges the Azure "Internet" service tag excludes. Deliberately explicit
# rather than using ipaddress.is_private, which also flags documentation and
# benchmark ranges that are topologically public.
NON_INTERNET = [
    ipaddress.ip_network(cidr) for cidr in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
        "fc00::/7", "fe80::/10",
    )
]

# Azure service tags we cannot reason about. A tag only covers itself.
OPAQUE_TAGS = {
    "virtualnetwork", "azureloadbalancer", "azurecloud", "storage",
    "sql", "azuretrafficmanager", "apimanagement", "gatewaymanager",
}


def _protocol_covers(earlier, later):
    """Does the earlier rule's protocol include the later rule's?"""
    a = str(earlier).lower()
    b = str(later).lower()
    if a in ("*", "all", "-1"):
        return True
    return a == b


def _ports_cover(earlier, later):
    """Does the earlier rule's port range contain the later rule's?"""
    return (earlier["from_port"] <= later["from_port"]
            and earlier["to_port"] >= later["to_port"])


def _as_network(value):
    """Parse a CIDR or bare address, or return None if it isn't one."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _is_internet_routable(network):
    """True if the network sits outside the ranges Azure's Internet tag excludes."""
    for excluded in NON_INTERNET:
        if network.version != excluded.version:
            continue
        if network.subnet_of(excluded):
            return False
    return True


def _peer_covers(earlier, later):
    """Does the earlier rule's source (or destination) include the later's?

    Order matters here. The wildcard check has to come first, and the IP
    version check has to happen before any containment test -- an IPv4 rule
    cannot shadow an IPv6 rule no matter how broad it is.
    """
    a = str(earlier).strip().lower()
    b = str(later).strip().lower()

    if a in ANY_SOURCE:
        return True
    if a == b:
        return True

    # 0.0.0.0/0 covers all of IPv4, including private space and the
    # Internet tag. It covers nothing in IPv6.
    if a == ANY_V4:
        if b == "internet":
            return True
        net_b = _as_network(b)
        return net_b is not None and net_b.version == 4
    if a == ANY_V6:
        net_b = _as_network(b)
        return net_b is not None and net_b.version == 6

    # The Internet tag covers publicly routable space but not private ranges,
    # and it is narrower than 0.0.0.0/0.
    if a == "internet":
        if b in ANY_SOURCE or b in (ANY_V4, ANY_V6):
            return False
        net_b = _as_network(b)
        return net_b is not None and _is_internet_routable(net_b)

    if a in OPAQUE_TAGS or b in OPAQUE_TAGS:
        return False

    net_a = _as_network(a)
    net_b = _as_network(b)
    if net_a is None or net_b is None:
        return False
    if net_a.version != net_b.version:
        return False
    return net_b.subnet_of(net_a)


def _covers(earlier, later, peer_field):
    """Does the earlier rule match every packet the later rule would match?"""
    return (_protocol_covers(earlier["protocol"], later["protocol"])
            and _ports_cover(earlier, later)
            and _peer_covers(earlier[peer_field], later[peer_field]))


def classify_effects(records):
    """Add an 'effect' field to every record. Returns the same list.

    Records are grouped by NSG and direction, because inbound and outbound
    are separate priority chains -- an inbound rule at priority 100 has no
    bearing on an outbound rule at 200.
    """
    for record in records:
        record["effect"] = "effective"
        record["superseded_by"] = ""

    chains = {}
    for record in records:
        if record["platform"] != "Azure" or record["priority"] is None:
            continue
        key = (record["group_id"], record["direction"])
        chains.setdefault(key, []).append(record)

    for (_, direction), chain in chains.items():
        peer_field = "destination" if direction == "Outbound" else "source"
        chain.sort(key=lambda r: r["priority"])

        for index, rule in enumerate(chain):
            for earlier in chain[:index]:
                if earlier["priority"] == rule["priority"]:
                    continue
                if not _covers(earlier, rule, peer_field):
                    continue

                if earlier["action"].lower() == "deny":
                    rule["effect"] = "shadowed"
                else:
                    rule["effect"] = "redundant"
                rule["superseded_by"] = (
                    f"{earlier['rule_name']} (priority {earlier['priority']})"
                )
                break

    return records


if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from normalize import load_azure

    rules = classify_effects(load_azure("sample_data/azure_nsgs.json"))
    for rule in sorted(rules, key=lambda r: (r["group_name"], r["priority"])):
        note = f"  <- {rule['superseded_by']}" if rule["superseded_by"] else ""
        print(f"{rule['group_name']:10} {rule['priority']:>5}  "
              f"{rule['action']:5} {rule['port_label']:15} "
              f"{rule['source']:12} {rule['effect']:10}{note}")
