# Risk Rubric

Four preliminary levels, applied to what the configuration shows and nothing more.

The word *preliminary* is load-bearing. These ratings come from rule exports. They
don't survive contact with routing tables, load balancer configuration, or a resource
owner who knows why something exists — and they aren't meant to. The rating exists to
order the validation queue, not to close it.

---

## High

Broad public access to an administrative or sensitive capability.

- SSH or RDP from an unrestricted public source
- Database listeners reachable from a public source
- Administrative or management interfaces open publicly
- All-protocol, all-port rules from a public source
- Full TCP range from a public source

The common thread is that the source is unrestricted and the service hands over
meaningful control once you're past authentication.

**On authentication as a mitigation.** Strong authentication is a real control and
worth crediting in the write-up. It isn't a reason to downgrade. Authentication
protects identity; it doesn't remove the listening service from the internet, and it
doesn't help against a flaw in the daemon doing the authenticating. Encryption
protects content, not access.

---

## Medium

Materially broad access that needs a stronger justification than the configuration
supplies.

- Public application ports where the intended ingress path is unclear
- Database access from a large private range
- Any-protocol, any-port rules from a large internal CIDR
- Broad access to identity, logging, VDI, or management systems
- Rules whose purpose is plausible but whose source scope looks wider than needed

Most Medium findings are about *scope* rather than *service*. The access itself is
often legitimate; it's the size of the source that's questionable.

**Private addressing is not least privilege.** A `/16` may cover thousands of hosts
that have no business reaching a database. If one internal workload is compromised and
a route exists, the network layer won't stop it. Off the internet is not the same as
appropriately scoped.

---

## Needs Review

The configuration evidence isn't sufficient to rate confidently, and guessing would
manufacture certainty that isn't there.

- Public VPN listeners
- IPsec negotiation and NAT traversal ports
- Management tunnel listeners
- Monitoring collectors with unidentified senders
- Public listeners whose service purpose can't be determined from the export

These share a property: public access may be exactly correct. A VPN concentrator that
isn't publicly reachable isn't a VPN concentrator. Rating it High would be wrong, and
rating it Low would be unfounded.

What's missing is architecture context — which peers are expected, whether the source
can be narrowed, what's happening at the certificate and patching layers. That comes
from an owner, not an export.

Resist the pressure to collapse this into High/Medium/Low for tidiness. A rating
scheme that always produces a number, including when the analyst doesn't know, is a
scheme that can't be trusted when it does.

---

## Low

Hardening, hygiene, and lower-impact configuration issues.

- Unrestricted outbound access
- ICMP, public or private
- Redundant rules (see [AWS vs Azure evaluation](aws-vs-azure-evaluation.md))
- Shadowed or ineffective rules
- Rule names that don't match rule contents
- Obsolete rules and general cleanup

**On unrestricted egress.** AWS creates every security group with allow-all outbound
by default. Rating it Low reflects that it isn't inbound exposure and that its
presence usually indicates nobody changed a default, not that someone made a poor
decision.

This is the most arguable line in the rubric. Egress is a real exfiltration path, and
a team with a mature egress-filtering posture might reasonably rate it higher. Say
where you've drawn the line and why, so anyone who disagrees can move it deliberately
rather than discovering the assumption by accident.

Also worth noting: an export shows configured behaviour, not creation history. You
can see that egress is broad. You generally can't see whether the rule is an untouched
default or something deliberately recreated. Don't claim the latter.

---

## Risk is not status

Two different columns, tracking two different things. Conflating them is the most
common structural mistake in a findings workbook.

| | Question it answers | Example values |
|---|---|---|
| **Initial Risk Level** | How significant does this look? | High, Medium, Needs Review, Low |
| **Status** | Where is this in the workflow? | Needs Owner Validation, Pattern Finding, Validated, Accepted, Remediation Planned, Closed |

A finding can be **High** *and* **Needs Owner Validation**. That combination means the
exposure looks significant and nobody has confirmed the business context yet. It's the
normal state of a finding on the day it's written.

The confusing pair is **Needs Review** (a risk rating) and **Needs Owner Validation**
(a status). They're related but not the same:

- *Needs Review* — I can't assign a severity from this evidence
- *Needs Owner Validation* — someone needs to confirm the business or architecture
  context

A High finding needs owner validation. It doesn't need review — the severity is clear
enough, it's the justification that's missing.

---

## What the ratings don't claim

Worth stating explicitly wherever ratings are published.

A rating describes what the network control permits. It doesn't establish that a
public IP is assigned, that a route exists, that anything is listening, that
authentication is weak, or that any of it has ever been used.

Which means every rating is a hypothesis with an evidence trail attached, and every
one of them should be able to survive an owner saying *"that's in a private subnet."*
The right response to that is to update the rating, not to defend it.
