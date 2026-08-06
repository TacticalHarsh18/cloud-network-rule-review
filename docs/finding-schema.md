# Finding Schema

Each finding is one row. The row separates what was observed from what it might mean,
what's unknown, and what should happen — four things that get blurred together in most
security write-ups, usually to the write-up's cost.

---

## Identity fields

Enough to find the exact resource again without ambiguity.

| Field | Notes |
|---|---|
| Cloud Platform | AWS or Azure |
| Account / Subscription | Which one |
| Group ID | **The authoritative identifier** |
| Group Name | Convenience only |
| Associated Resource | Or an explicit "not confirmed from this export" |
| Direction | Inbound or outbound |
| Protocol / Port | As configured |
| Source / Destination | As configured |
| Rule Name | Azure |
| Priority | Azure |
| Action | Azure — Allow or Deny |

**Group ID is the identifier and Group Name is a label.** Names repeat across accounts
and resource groups, and they drift from what the rule actually does. Anyone
following up on a finding needs to land on exactly one resource, which means keying to
ID everywhere and treating the name as decoration.

Where a field can't be filled in, record that it couldn't rather than leaving it
blank. "Not confirmed from this export" is information. An empty cell is ambiguous —
the reader can't tell whether you checked.

---

## The four analyst fields

This is the part that carries the review.

### Observation — evidence

What is configured, what traffic it permits, why that might matter, and what couldn't
be confirmed.

> Inbound TCP 22 is allowed from 0.0.0.0/0, permitting SSH connection attempts from
> unrestricted IPv4 sources. The associated resource and owner have not been
> confirmed.

Written in configuration language. It describes the rule. It doesn't claim anyone
connected, that the host is reachable, or that anything is compromised — and it names
its own gaps in the last sentence, so a reader knows the boundary of the claim without
having to ask.

### Initial Risk Level — significance

One of High, Medium, Needs Review, or Low. See the
[risk rubric](risk-rubric.md).

Separate from the observation on purpose. The observation is what anyone with the
export would see; the rating is a judgement about it. Keeping them in different
columns means someone can disagree with your rating without disputing your evidence,
which is a much more productive argument to have.

### Question for Owner — missing context

What you need from the person responsible before this can be resolved.

> Is direct SSH access from the internet required for this resource? If so, what
> compensating controls are in place, and can access be restricted to an approved VPN,
> bastion, or administrative IP range?

Not *"is this rule needed?"* — that's a yes/no question that produces a yes and ends
the conversation. The question should gather the information that determines the
answer: why it exists, which systems need it, whether the source can be narrowed, what
else is protecting it.

A good owner question can change the rating. If it can't, it isn't doing anything.

### Recommended Next Step — conditional action

What should happen *after* the requirement is confirmed.

> Confirm the associated resource, responsible owner, and business requirement. If
> unrestricted SSH is not required, limit TCP 22 to approved VPN, bastion, or
> administrative source ranges.

Note the conditional. A reviewer working from exports doesn't know whether the access
is required, so the recommendation can't assume it isn't. Recommendations phrased as
instructions get either ignored or followed — and the second outcome breaks
production and ends the credibility of the whole review.

Every recommendation should also be least-disruptive and routed through change
control. "Restrict the source" beats "remove the rule."

---

## Classification fields

| Field | Purpose |
|---|---|
| Finding Type | Which recurring pattern this belongs to |
| Status | Where the row sits in the workflow |

A closed vocabulary for Finding Type is worth the effort. Free text produces forty
variations of the same category and makes the summary counts meaningless. Something
like:

- Unrestricted Inbound Access
- Public Administrative Access
- Public Database Access
- Public Application Access
- Public VPN or Tunnel Access
- Public Monitoring or ICMP Access
- Broad Internal Access
- Unrestricted Outbound Access
- Rule Hygiene or Ineffective Rule

Status tracks disposition, not severity:

```
Needs Owner Validation
        ↓
    Validated
        ↓
Accepted  or  Remediation Planned
        ↓
     Closed
```

**Pattern Finding** sits outside that chain. It marks a row as one instance of a
repeated condition — useful for governance and for spotting systemic issues, but not
a step between Needs Owner Validation and Validated. Keeping it off the workflow
prevents the chain from becoming incoherent.

---

## Counting

One row is one rule, on one group, in one direction. Which means:

- IPv4 and IPv6 produce separate rows — they're separately configured permissions
- Inbound and outbound produce separate rows
- One group can produce many rows

A single service group with public inbound on v4 and v6 plus default outbound on v4
and v6 produces four rows on its own.

**Report rule rows and unique resources side by side, always.** They answer different
questions. Rule rows measure remediation work; unique resources measure how much of
the estate is affected. Publishing only the first invites the reading that every row
is a separate problem. Publishing only the second hides the volume of work.

Label every number with which one it is. It takes four extra words and saves the
argument.
