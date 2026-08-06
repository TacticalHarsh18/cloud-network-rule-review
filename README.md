# cloud-network-rule-review

# Cloud Network Rule Review

A methodology for reviewing AWS Security Group and Azure Network Security Group
configurations across multi-cloud environments, and the risk framework that goes
with it.

This is documentation, not a scanner. The hard part of reviewing cloud network rules
isn't finding `0.0.0.0/0` — that's a text search. The hard part is deciding which
matches are actually findings, rating them honestly when you can't see the whole
architecture, and reporting the result in a way the people who own those systems can
act on.

## The problem

A large cloud estate accumulates network rules faster than anyone reviews them.
Groups get created during instance setup with default permissions and never revisited.
Temporary access becomes permanent. Rule names stop matching rule contents. Ownership
gets lost when people change teams.

Reviewing that estate raises four questions per rule:

1. What traffic does this rule permit?
2. Is that broader than the service appears to need?
3. How significant is it, given only the configuration evidence?
4. What does the owner need to tell me before anyone changes anything?

The last one matters most. A network review that produces instructions gets ignored
or, worse, followed — and something breaks. A review that produces questions gets
answered.

## What's here

| Document | What it covers |
|---|---|
| [AWS vs Azure rule evaluation](docs/aws-vs-azure-evaluation.md) | Why the same rule text means different things on each platform, and how to classify Azure rules as effective, redundant, or shadowed |
| [Risk rubric](docs/risk-rubric.md) | A four-level preliminary rating scheme, and why one of the levels is "I can't tell yet" |
| [Finding schema](docs/finding-schema.md) | The record structure, and why evidence, interpretation, and action stay in separate fields |

Read the AWS vs Azure document first if you only read one. It's the piece that
changes how the analysis works rather than how it's presented.

## The central limitation

A permissive rule proves that the cloud network control allows matching traffic. It
does not prove:

- a public IP is assigned
- a route to the internet exists
- anything is listening on that port
- authentication would fail
- any of it was ever used

Which means a review like this identifies *potential* exposure and a need for
validation. It does not identify compromise, and writing it up as though it does will
cost you the room the first time an engineer points out that the subnet is private.

Every finding should be able to survive the sentence: *"the rule permits this; I
didn't verify reachability."*

## Scope

Applies to AWS Security Groups and Azure NSGs. Doesn't cover NACLs, host firewalls,
WAF rules, service-level policy, or anything above the network layer. Those can all
change the practical risk of a given finding, which is part of why ratings coming out
of this process are preliminary.

## Notes

Written after running a configuration review across a production multi-cloud estate.
Contains no data, findings, or configuration from any real environment — the examples
throughout use synthetic group names and
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation addresses.

MIT licensed. Use whatever's useful.
