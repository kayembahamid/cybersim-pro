# CyberSim Pro Usage Policy & Ethics Guide

CyberSim Pro is a defensive training and readiness platform. Use it responsibly to improve resilience, never to inflict harm. This guide helps security leaders document acceptable use and align with regulatory expectations.

---

## 1. Core Principles
- **Authorized environments only**: operate in isolated labs or approved sandboxes. Production data and systems are out of scope.
- **Defensive intent**: every exercise must have a training, validation, or risk-reduction objective. Malicious experimentation is prohibited.
- **Transparency & accountability**: maintain audit trails (`logs/audit.log`), playbooks, and sign-offs for every session.
- **Respect privacy**: use synthetic identities and scrub real customer or employee data from outputs.

---

## 2. Governance Workflow
1. **Exercise proposal**
   - Define scenario goals, participating teams, anticipated MITRE tactics, and success criteria.
   - Obtain written approval from the CISO (or delegated authority).
2. **Pre-flight checklist**
   - Confirm lab isolation, network rules, access rights, and logging configuration.
   - Load role-based prompt templates to enforce context.
   - Assign facilitators for red, blue, purple, and executive engagement.
3. **Execution & monitoring**
   - Keep `stop_simulation` tool readily available in case the exercise needs to be halted.
   - Stream outputs to observers without exposing raw payloads.
   - Document decisions in real time (chat transcript, shared notebook, or ticketing system).
4. **Post-exercise actions**
   - Review audit log entries for completeness (who, what, when, why).
   - Deliver reports to stakeholders within 48 hours.
   - File artefacts in the evidence repository following retention policies.

---

## 3. Regulatory Alignment
- **PCI DSS**: Map simulations involving cardholder data environments to requirement 12 (security testing) and retain audit logs for one year.
- **HIPAA**: Treat Healthcare scenarios as part of risk analysis (45 CFR §164.308). Ensure no PHI enters the lab.
- **SOX**: Record exercises that touch financial reporting systems and align findings with internal control assessments.
- **GDPR / Privacy acts**: When modelling EU data subjects, perform a DPIA and anonymise inputs.

---

## 4. Safety Controls Checklist
- [ ] Lab network segmentation verified
- [ ] Audit logging enabled and tested
- [ ] `stop_simulation` tool tested before live session
- [ ] Role-based prompts distributed to participants
- [ ] Communication plan (chat channel, bridge line) active
- [ ] Data retention & destruction plan confirmed

---

## 5. Incident Handling
If CyberSim Pro outputs or artefacts escape the lab or are misused:
1. Invoke the organisation’s incident response plan.
2. Use the audit log to identify the session, operators, and context.
3. Notify the CISO, legal, and compliance teams immediately.
4. Contain, eradicate, and document the mishandling, then review controls before resuming exercises.

---

## 6. Ethics Pledge
Participants must acknowledge:
- I will use CyberSim Pro solely for defensive training.
- I will not replicate payloads or artefacts into production environments.
- I will respect confidentiality of scenarios, findings, and audit logs.
- I will report any suspected misuse immediately.

Retain signed acknowledgements (digital or physical) for audit purposes.

---

Maintaining strong governance ensures CyberSim Pro remains a trusted training asset for defenders, executives, and regulators alike.
