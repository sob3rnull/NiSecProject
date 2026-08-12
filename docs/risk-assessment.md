# Risk assessment — derived, not asserted

The submitted proposal rates each threat High/Medium/Low without showing how the
rating was reached. `report-skeleton.md` §3.7 already flags this: *"consider
adding Likelihood and Impact columns so the rating is derived rather than
asserted."* This document does that.

A rating you can reconstruct is worth several that you cannot. In a viva, "why
is this High?" has a real answer here.

Method follows the qualitative approach of **NIST SP 800-30 Rev. 1** (*Guide for
Conducting Risk Assessments*): score likelihood and impact on defined ordinal
scales, derive risk as their product, then re-score after controls to obtain
residual risk.

---

## 1. Scales

**Likelihood** — probability of occurrence against a small-organisation server
over one year.

| Score | Band | Meaning |
|---|---|---|
| 5 | Almost certain | Continuous/automated; happens to any exposed host |
| 4 | Likely | Expected multiple times per year |
| 3 | Possible | Plausible once per year |
| 2 | Unlikely | Requires motivation or specific targeting |
| 1 | Rare | Requires capability most attackers lack |

**Impact** — consequence to confidentiality, integrity or availability if it
succeeds.

| Score | Band | Meaning |
|---|---|---|
| 5 | Severe | Business stops; data destroyed or published |
| 4 | Major | Account or host compromised; recovery needed |
| 3 | Moderate | Service degraded; contained and recoverable |
| 2 | Minor | Limited effect; no data or availability loss |
| 1 | Negligible | No direct harm; enables a later step |

**Risk = Likelihood × Impact.**  1–4 Low · 5–9 Medium · 10–16 High · 17–25 Critical

---

## 2. Inherent risk (before this system exists)

| # | Threat | L | I | Risk | Justification |
|---|---|:-:|:-:|:-:|---|
| 1 | Port scanning | 5 | 1 | **5 — Medium** | Constant automated background traffic, but scanning alone causes no harm; it is reconnaissance for a later step |
| 2 | Brute-force login | 5 | 4 | **20 — Critical** | Any host with SSH reachable is attacked continuously; success yields a real account |
| 3 | Malware / ransomware | 3 | 5 | **15 — High** | Needs a delivery route, but the consequence is total: encrypted data and stopped operations |
| 4 | Unauthorized access | 3 | 4 | **12 — High** | Default or weak credentials on management interfaces are a common and directly exploitable route |
| 5 | DoS attack | 2 | 3 | **6 — Medium** | Requires motivation to target this org specifically; effect is availability loss, recoverable |
| 6 | Suspicious network traffic | 4 | 2 | **8 — Medium** | Frequent, but usually an indicator of something else rather than damaging in itself |
| 7 | Misconfiguration | 4 | 4 | **16 — High** | Very common in hand-built systems, and it silently enables threats 2, 3 and 4 |

### Where this disagrees with the proposal — and why that is the point

| Threat | Proposal said | Derived | Why the derivation is better |
|---|---|---|---|
| Port scanning | Medium | **Medium (5)**, but driven entirely by likelihood, impact 1 | Same label, different reason. Scanning is near-certain and near-harmless. Treating it as mid-tier *risk* rather than mid-tier *nuisance* misdirects effort |
| Brute-force login | High | **Critical (20)** | Both maximal-likelihood and major-impact. The proposal's top band was "High", so this was invisible |
| DoS attack | Medium | **Medium (6)** — bottom of the band | Sits one point above Low. Ranking it beside misconfiguration (16) overstates it by a factor of nearly three |
| Misconfiguration | Medium | **High (16)** | Underrated in the proposal. It is both likely and a force multiplier for everything else |

Two ratings moved and one changed its justification. **Do not quietly overwrite
the proposal's table** — show both and explain the change. Revising an earlier
judgement with stated reasoning is evidence of analysis; silently replacing it
looks like you forgot what you wrote.

---

## 3. Residual risk (with this system deployed)

Here is the part that most student reports get wrong.

> **A detective control does not reduce likelihood.** Suricata does not make you
> less likely to be scanned or brute-forced. It reduces *impact*, by shortening
> the time between compromise and response.

So in the table below **L is almost unchanged** and only **I moves** — and it
only moves as far as the response process behind the alert allows.

| # | Threat | L | I | Residual | Control doing the work |
|---|---|:-:|:-:|:-:|---|
| 1 | Port scanning | 5 | 1 | **5 — Medium** | Detection only; impact was already 1 so there is nothing to reduce |
| 2 | Brute-force login | 5 | 3 | **15 — High** | Wazuh 5710/5712 alert within seconds; impact drops 4→3 only because response is manual |
| 3 | Malware / ransomware | 3 | 4 | **12 — High** | FIM 100200–100202 detects the drop and the mass-modify; earlier detection limits blast radius but does not prevent encryption |
| 4 | Unauthorized access | 2 | 3 | **6 — Medium** | The only genuine *likelihood* reduction, because `harden-dashboard.sh` is a **preventive** control: firewall, no default creds, timeout |
| 5 | DoS attack | 2 | 3 | **6 — Medium** | Detection does not mitigate a flood. Unchanged — say so |
| 6 | Suspicious network traffic | 4 | 1 | **4 — Low** | ET Open plus custom SIDs make it visible rather than damaging |
| 7 | Misconfiguration | 3 | 4 | **12 — High** | Wazuh SCA audits against CIS continuously; likelihood drops only if findings are acted on |

### What the residual column actually proves

- **Only threat 4 dropped in likelihood**, and only because part of the response
  to it was preventive rather than detective. This is the single clearest
  demonstration in the project of why detection alone is not a security
  strategy — and it is a measured architectural claim, not an opinion.
- **Nothing reached Low except threat 6.** A semester of work moved one Critical
  to High and one High to Medium. That is an honest outcome and a far stronger
  result than a table where every risk conveniently becomes Low.
- **The ceiling on every reduction is the response process.** Impact drops
  4→3, not 4→1, because a human has to see the alert and act. Enabling the
  active response in `config/wazuh-manager/active-response.xml` is what would
  move those further — and quantifying that with `make measure` before and
  after is the strongest piece of future work available here.

---

## 4. Feeding this into the report

- §3.7 — both tables, plus the disagreement table and its reasoning.
- §7.4 — the residual column is your limitations section, already quantified.
- §7.5 — recommendations follow directly: the rows that did not improve are
  exactly the controls the system still lacks.
- Viva — if asked "what is your biggest remaining risk?", the answer is
  brute-force login at residual 15, and the reason is that response is manual.
