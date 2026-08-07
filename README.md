# Cloud Network Rule Review

A methodology and analyzer for reviewing AWS Security Group and Azure Network Security
Group configurations across multi-cloud environments.

Finding `0.0.0.0/0` in a rule export is a text search. The hard part is deciding which
matches are actually findings, rating them honestly when you can't see the whole
architecture, and reporting the result so the people who own those systems can act on
it.

This repo contains the reasoning ([docs](#documentation)) and a tool that implements it
([src](#how-it-works)).

## Quick start

No dependencies beyond the Python standard library. Python 3.8+.

```bash
git clone https://github.com/TacticalHarsh18/cloud-network-rule-review.git
cd cloud-network-rule-review

python src/analyze.py \
  --aws sample_data/aws_security_groups.json \
  --azure sample_data/azure_nsgs.json \
  --out output/findings.csv
```

To run it against a real estate, produce the exports with:

```bash
aws ec2 describe-security-groups --output json > aws_security_groups.json
az network nsg list --output json > azure_nsgs.json
```

Either input is optional — pass `--aws`, `--azure`, or both.

## Sample output

Against the synthetic data in this repo:

```
  Rules examined     29
  Findings           25
  Scoped, no finding 4

  By risk level
    High              7 rows      6 groups
    Medium            6 rows      4 groups
    Needs Review      2 rows      1 groups
    Low              10 rows     10 groups

  By finding type
    Broad Internal Access                3 rows      2 groups
    Public Administrative Access         4 rows      3 groups
    Public Application Access            3 rows      2 groups
    Public Database Access               1 rows      1 groups
    Public VPN or Tunnel Access          2 rows      1 groups
    Rule Hygiene or Ineffective Rule     2 rows      2 groups
    Unrestricted Inbound Access          2 rows      2 groups
    Unrestricted Outbound Access         8 rows      8 groups
```

Counts appear as both rule rows and unique resources because they answer different
questions. Rows measure remediation work. Resources measure how much of the estate is
affected. Reporting only the first invites the reading that every row is a separate
problem; reporting only the second hides the volume.

The CSV carries the full record for each finding: identity fields, the observation, a
preliminary risk level, a question for the resource owner, and a conditional next step.

## Why the Azure handling matters

Azure evaluates NSG rules in priority order and stops at the first match. A rule can be
present, look serious, and decide nothing at all.

```
Priority  Name                      Action  Port   Source
100       AllowAnyCustomAnyInbound  Allow   *      *
300       AllowSSHInbound           Allow   22     *
```

A tool that searches for SSH open to the internet reports the rule at priority 300 as a
critical finding. It isn't. Priority 100 already permits that traffic, so removing the
SSH rule would change nothing — the exposure belongs to the earlier rule.

This analyzer reports it correctly:

```
High   Azure  mgmt-nsg  Allow  All traffic  *   Unrestricted Inbound Access
Low    Azure  mgmt-nsg  Allow  TCP 22       *   Rule Hygiene or Ineffective Rule
```

One exposure, attributed to the rule that causes it, plus a hygiene note on the rule
that doesn't. Getting this wrong inflates the Azure risk count and sends remediation at
the wrong rule.

Full explanation, including shadowed rules: [AWS vs Azure rule
evaluation](docs/aws-vs-azure-evaluation.md).

## How it works

```
exports ──> normalize ──> classify effects ──> detect patterns ──> findings.csv
```

| Module | Role |
|---|---|
| `src/normalize.py` | Flattens both export formats into one rule record per permitted path. IPv4 and IPv6 become separate records, because they are separately configured permissions. |
| `src/azure_priority.py` | Walks each NSG's priority chain and marks every rule effective, redundant, or shadowed. AWS rules are effective by definition — no priority, no Deny. |
| `src/rules.py` | Maps each rule to a finding type and preliminary risk level, and attaches an owner question and next step. Returns nothing for appropriately scoped rules. |
| `src/analyze.py` | Entry point. Reads, runs the pipeline, writes CSV, prints the summary. |

Each module runs standalone for inspection:

```bash
python src/normalize.py         # what the normalized records look like
python src/azure_priority.py    # effect classification per rule
```

## Repository layout

```
docs/           the reasoning: platform differences, risk rubric, record schema
src/            the analyzer
sample_data/    synthetic AWS and Azure exports, seeded with every pattern
output/         generated, not tracked
```

## Documentation

| Document | Covers |
|---|---|
| [AWS vs Azure rule evaluation](docs/aws-vs-azure-evaluation.md) | Cumulative allow versus priority-ordered first match, and how to classify effective, redundant, and shadowed rules |
| [Risk rubric](docs/risk-rubric.md) | The four preliminary levels, and why one of them is "I can't tell yet" |
| [Finding schema](docs/finding-schema.md) | The record structure, and why evidence, interpretation, and action stay in separate fields |

Read the first one if you only read one. It changes how the analysis works rather than
how it's presented.

## What this does not establish

A permissive rule proves the cloud network control allows matching traffic. It does not
prove a public IP is assigned, a route exists, anything is listening, authentication
would fail, or that any of it was ever used.

Every rating here is preliminary and should survive the sentence *"the rule permits
this; I didn't verify reachability."* When a resource owner says a subnet is private,
the right response is to update the rating, not defend it.

## Known limitations

- **AWS group unions aren't computed.** An instance with several security groups
  attached has the union of their permissions. The export doesn't say which groups are
  attached to which resource, so each group is assessed alone.
- **Coverage is pairwise.** A rule is compared against each earlier rule individually,
  so two earlier rules that jointly cover a later one won't be detected. Rare in
  practice, and full interval-union logic costs more than it's worth here.
- **Opaque service tags.** Azure tags like `VirtualNetwork` and `AzureLoadBalancer`
  resolve to address space the export doesn't contain, so they're treated as covering
  only themselves.
- **Port-based service inference.** A finding on TCP 3306 assumes MySQL. Non-standard
  ports won't be categorized correctly.
- **No NACLs, host firewalls, WAF, or application controls.** All of these can change
  the practical risk of a finding.

## Notes

Written after running a configuration review across a production multi-cloud estate.
Contains no data, findings, or configuration from any real environment — everything
here uses synthetic group names and
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation addresses.

MIT licensed.
