"""Decide whether a normalized rule is a finding, and how significant it looks.

The ratings here are preliminary by design. They come from configuration
exports, which show what a rule permits and nothing else -- not whether a
public IP is assigned, whether a route exists, whether anything is listening,
or whether authentication would hold. See docs/risk-rubric.md.

Order of evaluation matters. An Azure rule that never takes effect is a hygiene
issue regardless of which port it names, so that check runs before anything
looks at ports.
"""

import ipaddress

PUBLIC_SOURCES = {"0.0.0.0/0", "::/0", "*", "any", "internet"}

ADMIN_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    5985: "WinRM", 5986: "WinRM over TLS",
}

DATABASE_PORTS = {
    1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
    11211: "Memcached", 9042: "Cassandra",
}

VPN_TUNNEL_PORTS = {
    500: "IKE", 1194: "OpenVPN", 4500: "IPsec NAT-T",
    943: "VPN admin", 8305: "management tunnel",
}

ADMIN_INTERFACE_PORTS = {8443: "admin web interface", 10000: "admin panel"}

# Names implying a restriction the rule may not actually have.
RESTRICTIVE_NAME_HINTS = ("myip", "trusted", "office", "corp", "internal",
                          "private", "vpn", "mgmt", "restricted", "allowlist")


def is_public(peer):
    """True if the source or destination is unrestricted."""
    return str(peer).strip().lower() in PUBLIC_SOURCES


def broad_private_prefix(peer):
    """Return the prefix length if this is a large private range, else None.

    A /16 or wider covers thousands of hosts. Private addressing keeps traffic
    off the internet; it does not make the scope appropriate.
    """
    try:
        network = ipaddress.ip_network(str(peer).strip(), strict=False)
    except (ValueError, TypeError):
        return None
    if not network.is_private:
        return None
    if network.version == 4 and network.prefixlen <= 16:
        return network.prefixlen
    if network.version == 6 and network.prefixlen <= 48:
        return network.prefixlen
    return None


def _covers_everything(rule):
    """All protocols and the whole port range."""
    return (str(rule["protocol"]).lower() in ("all", "*", "-1")
            or (rule["from_port"] == 0 and rule["to_port"] == 65535))


def _named_port(rule, table):
    """Return the service name if the rule's range targets a port in table."""
    for port, name in table.items():
        if rule["from_port"] <= port <= rule["to_port"]:
            return port, name
    return None, None


def _is_icmp(rule):
    return str(rule["protocol"]).lower() in ("icmp", "icmpv6", "1", "58")


def name_looks_misleading(rule):
    """Azure rule whose name implies a restriction its source doesn't have."""
    if not rule.get("rule_name"):
        return False
    if not is_public(rule.get("source", "")):
        return False
    lowered = rule["rule_name"].lower()
    return any(hint in lowered for hint in RESTRICTIVE_NAME_HINTS)


# ----------------------------------------------------------------------
# Finding definitions: type -> (risk, owner question, next step)
# ----------------------------------------------------------------------

FINDING_GUIDANCE = {
    "Unrestricted Inbound Access": (
        "High",
        "Which protocols, ports, and client sources are actually required?",
        "Replace the unrestricted rule with specific sources, protocols, and "
        "ports once the requirement is confirmed.",
    ),
    "Public Administrative Access": (
        "High",
        "Is administrative access from public sources required, and what is "
        "the approved management path?",
        "Confirm the owner and approved path, then restrict the source to a "
        "VPN, bastion, or management network through change control.",
    ),
    "Public Database Access": (
        "High",
        "Is public database connectivity required, and which clients need it?",
        "Restrict the source to application security groups, private ranges, "
        "or specific trusted addresses once clients are identified.",
    ),
    "Public Application Access": (
        "Medium",
        "Is this the intended public entry point, or should traffic arrive "
        "through a load balancer or gateway?",
        "Confirm the intended ingress path. Where a load balancer fronts the "
        "service, restrict the source to the load balancer's security group.",
    ),
    "Public VPN or Tunnel Access": (
        "Needs Review",
        "Is this an approved public listener, and which peers require access?",
        "Confirm the architecture and owner. Restrict to known peer ranges "
        "where feasible and verify authentication, certificates, and patching.",
    ),
    "Public Monitoring or ICMP Access": (
        "Low",
        "Which monitoring systems are expected to originate this traffic?",
        "Narrow the source to approved collectors or management networks.",
    ),
    "Broad Internal Access": (
        "Medium",
        "Which applications or systems actually require this access, and can "
        "the source range be narrowed?",
        "Replace the broad range with a source security group, application "
        "security group, or specific subnet.",
    ),
    "Unrestricted Outbound Access": (
        "Low",
        "Is unrestricted egress the approved baseline, or can it be limited "
        "to required destinations and ports?",
        "Define workload-specific egress requirements. Note that broad egress "
        "is the default on newly created AWS security groups.",
    ),
    "Rule Hygiene or Ineffective Rule": (
        "Low",
        "Is this rule obsolete, incorrectly ordered, or documenting an "
        "intended future state?",
        "Remove or reorder the rule. The exposure, if any, belongs to the "
        "earlier rule that takes effect.",
    ),
}


def classify(rule):
    """Return a finding dict, or None if the rule is appropriately scoped."""
    finding_type = None
    observation = None

    effect = rule.get("effect", "effective")
    peer = rule["destination"] if rule["direction"] == "Outbound" else rule["source"]

    # An Azure rule that never decides anything is a hygiene issue, whatever
    # port it names. This has to run first or the exposure gets counted twice.
    if effect in ("redundant", "shadowed"):
        finding_type = "Rule Hygiene or Ineffective Rule"
        observation = (
            f"Rule {rule['rule_name']} at priority {rule['priority']} is "
            f"{effect}: {rule['superseded_by']} already matches this traffic. "
            f"The rule does not change effective access."
        )

    elif str(rule["action"]).lower() == "deny":
        # A Deny rule blocks traffic. It is never exposure, however broad it
        # looks. An ineffective Deny is still caught above as a hygiene issue.
        return None

    elif rule["direction"] == "Outbound":
        if is_public(peer) and _covers_everything(rule):
            finding_type = "Unrestricted Outbound Access"
            observation = (
                f"Outbound access permits all protocols and ports to {peer}. "
                f"This does not create inbound exposure but may exceed what "
                f"the workload requires."
            )

    elif is_public(peer):
        admin_port, admin_name = _named_port(rule, ADMIN_PORTS)
        db_port, db_name = _named_port(rule, DATABASE_PORTS)
        vpn_port, vpn_name = _named_port(rule, VPN_TUNNEL_PORTS)
        iface_port, iface_name = _named_port(rule, ADMIN_INTERFACE_PORTS)

        if _covers_everything(rule):
            finding_type = "Unrestricted Inbound Access"
            observation = (
                f"Inbound access permits all protocols and ports from {peer}. "
                f"The rule does not create listening services, but it removes "
                f"the network restriction from any service active now or later."
            )
        elif admin_port:
            finding_type = "Public Administrative Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}, "
                f"permitting {admin_name} connection attempts from "
                f"unrestricted sources."
            )
        elif db_port:
            finding_type = "Public Database Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}, "
                f"permitting {db_name} connection attempts from unrestricted "
                f"sources."
            )
        elif iface_port:
            finding_type = "Public Administrative Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}, "
                f"exposing an {iface_name} to unrestricted sources."
            )
        elif vpn_port:
            finding_type = "Public VPN or Tunnel Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}. "
                f"Public reachability may be required for {vpn_name}, so the "
                f"intended architecture needs confirmation."
            )
        elif _is_icmp(rule):
            finding_type = "Public Monitoring or ICMP Access"
            observation = f"ICMP is allowed from {peer}."
        else:
            finding_type = "Public Application Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}. "
                f"Public application access may be intended, but the approved "
                f"ingress path is not established by the rule alone."
            )

    else:
        prefix = broad_private_prefix(peer)
        if prefix is not None and not _is_icmp(rule):
            finding_type = "Broad Internal Access"
            observation = (
                f"Inbound {rule['port_label']} is allowed from {peer}, a "
                f"/{prefix} private range. Private addressing limits internet "
                f"exposure but does not narrow the scope to required systems."
            )

    if finding_type is None:
        return None

    risk, question, next_step = FINDING_GUIDANCE[finding_type]

    notes = []
    if name_looks_misleading(rule):
        notes.append(
            f"Rule name '{rule['rule_name']}' implies a source restriction "
            f"that the rule does not apply."
        )
    if rule["ip_version"] == "IPv6":
        notes.append("IPv6 counterpart of an equivalent IPv4 permission.")

    return {
        "Finding Type": finding_type,
        "Status": "Needs Owner Validation",
        "Cloud Platform": rule["platform"],
        "Account": rule["account"],
        "Group ID": rule["group_id"],
        "Group Name": rule["group_name"],
        "Direction": rule["direction"],
        "Rule Name": rule["rule_name"],
        "Priority": rule["priority"] if rule["priority"] is not None else "",
        "Action": rule["action"],
        "Protocol/Port": rule["port_label"],
        "Source": rule["source"],
        "Destination": rule["destination"],
        "Azure Effect": effect if rule["platform"] == "Azure" else "",
        "Observation": observation,
        "Initial Risk Level": risk,
        "Question for Owner": question,
        "Recommended Next Step": next_step,
        "Notes": " ".join(notes),
    }


def analyze(rules):
    """Turn normalized rules into findings, dropping scoped rules."""
    findings = []
    for rule in rules:
        finding = classify(rule)
        if finding:
            findings.append(finding)
    return findings
