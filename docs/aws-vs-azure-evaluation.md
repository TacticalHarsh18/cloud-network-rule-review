# AWS and Azure Evaluate Rules Differently

Two rules can be written identically on AWS and Azure and mean completely different
things. If you analyse both platforms the same way, you will over-report Azure — and
the over-reporting is invisible unless you know to look for it.

## The short version

**AWS Security Groups** are allow-only and cumulative. No ordering. If any rule on any
attached group permits the traffic, the traffic is permitted.

**Azure NSGs** support Allow and Deny, and evaluate rules in priority order. The
lowest priority number that matches decides the outcome. Nothing after it is
consulted.

That difference means an Azure rule can look serious and do nothing at all.

---

## AWS: cumulative allow

AWS Security Groups contain only allow rules. There is no deny, no priority number,
and no ordering. An instance can have several groups attached, and the effective
permission is the union of all of them.

```
web-tier-sg
  inbound  TCP 443    from 0.0.0.0/0
  inbound  TCP 22     from 198.51.100.10/32

legacy-access-sg          (also attached to the same instance)
  inbound  TCP 22     from 0.0.0.0/0
```

Effective inbound SSH here is `0.0.0.0/0`. The narrow rule in `web-tier-sg` does not
constrain the broad rule in `legacy-access-sg`. There's no precedence to appeal to —
both rules simply exist, and both permit.

This has a practical consequence for review. **You cannot rate an AWS rule by looking
at it alone.** A tightly scoped rule tells you nothing if a second group attached to
the same resource is wide open. The analysis question is always *"does any applicable
rule permit this traffic?"*, never *"does this rule permit it?"*

The corresponding evidence gap: unless the export tells you which groups are attached
to which resources, you can't compute the union. Note that limitation rather than
implying you evaluated it.

---

## Azure: priority-ordered first match

Azure NSG rules carry a priority number, typically 100–4096. Evaluation walks from the
lowest number upward and stops at the first rule matching the traffic. That rule's
action — Allow or Deny — is the result.

This creates three states a rule can be in.

### Effective

The rule is the first match for its traffic. It decides the outcome.

```
Priority  Name                      Action  Port      Source
100       AllowHTTPSInbound         Allow   443       Internet
200       AllowSSHFromMgmt          Allow   22        198.51.100.0/24
4096      DenyAllInbound            Deny    *         *
```

All three are effective. Each one is the first rule matching its own traffic.

### Redundant

An earlier rule already allows the traffic. The later rule permits nothing new.

```
Priority  Name                      Action  Port      Source
100       AllowAnyCustomAnyInbound  Allow   *         *
300       AllowSSHInbound           Allow   22        *
```

Priority 100 allows everything from anywhere. By the time evaluation reaches priority
300, port 22 has already been allowed — the SSH rule never decides anything.

Rating that SSH rule as a High public-administrative finding would be wrong twice
over. It reports exposure that the priority-100 rule already accounts for, and it
implies that removing the SSH rule would reduce access. It wouldn't. The exposure
belongs to priority 100.

The SSH rule is still worth recording, as a low-severity hygiene finding. A policy
containing rules that do nothing is harder to reason about, and the next person to
edit it may assume the SSH rule is what's granting access.

### Shadowed

An earlier rule denies the traffic. The later allow rule never takes effect.

```
Priority  Name                      Action  Port      Source
100       DenyAllInbound            Deny    *         *
110       AllowAppPortInbound       Allow   8080      Internet
```

Port 8080 is denied. The rule at 110 is inert — and this one is arguably a bigger
problem than a redundant rule, because someone believes that port is open. If the
application depends on it, it is already broken; if it isn't, the rule is misleading
documentation.

Shadowed rules are also worth flagging as a possible ordering mistake. The author
probably intended the allow to sit below the deny.

---

## How to classify a rule

For each Azure rule, sort the NSG's rules by priority ascending, then walk from the
lowest number up to the rule you're evaluating and ask whether any earlier rule
matches the same traffic.

- No earlier match → **effective**. Rate it normally.
- Earlier match with Allow → **redundant**. Low, hygiene.
- Earlier match with Deny → **shadowed**. Low, hygiene, and probably a bug.

"Matches the same traffic" means the earlier rule's protocol, port range, source, and
destination all cover the traffic your rule describes. Wildcards make this common —
`*` for protocol, port, or source will swallow almost anything below it.

Two things to remember:

**Default rules exist and are usually excluded.** Azure adds default rules at
priority 65000+ (`AllowVnetInBound`, `AllowAzureLoadBalancerInBound`, `DenyAllInBound`
and outbound equivalents). They apply to every NSG and aren't anyone's configuration
choice. Exclude them from rule counts, but do account for them when working out
effective behaviour — `DenyAllInBound` at 65500 is why anything not explicitly allowed
is blocked.

**Direction matters.** Inbound and outbound rules are separate priority chains. An
inbound rule at priority 100 has no bearing on an outbound rule at 200.

---

## Why this changes the numbers

Redundant rules cluster. An NSG with an allow-any rule near the top of the chain
tends to have several specific allow rules below it, because someone added the
allow-any as a stopgap and never removed the rules it superseded — or added specific
rules afterward, not realising they were already covered.

Treating every one of those as an independent High finding inflates the count for that
NSG by however many rules sit below the allow-any. The exposure is real, but it's one
exposure, not five.

The reverse error is worse in a different way. If you skip priority analysis entirely
and only rate rules that *look* dangerous, you'll miss the case where a mild-looking
allow-any at priority 100 is the actual source of exposure, and you'll write up the
SSH rule at 300 as the finding. The remediation then targets the wrong rule and
changes nothing.

---

## Practical notes

**Key everything to resource ID, not name.** Azure NSG names are unique only within a
resource group. The same name can legitimately appear several times across a
subscription, on genuinely different resources. Group name is a label; the ID is the
identity.

**Rule names are not evidence.** A rule called `AllowMyIpInbound` may have a source of
`*`. A rule named for one port may open a different one. Read the fields, not the
name, and treat a name/content mismatch as a finding in its own right — it's a
maintenance hazard even when the access is fine.

**IPv4 and IPv6 are separate rules on both platforms.** A group open to `0.0.0.0/0`
and `::/0` has two rules and one exposure. Decide early whether you're counting rules
or resources, and say which on every number you publish.

**Statefulness applies to both.** AWS Security Groups and Azure NSGs are both
stateful — return traffic for an allowed connection is permitted automatically. You
don't need a matching outbound rule for inbound traffic to work, which is why an
outbound review is about what a workload can *initiate*, not about responses.
