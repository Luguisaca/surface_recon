# INTERNAL Security Policy

Surface_Recon INTERNAL is the private engineering authority for LAB-001. Repository privacy does not authorize storing secrets or unrelated sensitive data and does not make internal material suitable for PUBLIC promotion.

## Security invariants

- Use Surface_Recon only against systems and scopes the operator is authorized to assess.
- Never commit credentials, tokens, private keys, client secrets or unnecessary personal/customer data.
- Treat discovered hosts, services, evidence, tool output and imported artifacts as potentially sensitive and untrusted.
- Do not silently install tools, use credentials, contact external services, exploit targets or perform destructive actions.
- Coverage claims require evidence. A successful process does not prove complete discovery or absence of attack surface.
- Automated results and AI classifications are findings/candidates, not validated vulnerabilities by themselves.
- Security controls may not be weakened merely to make tests or gates pass.

## Evidence handling

Preserve provenance for material findings: target/scope context, tool/capability, invocation or reproducible parameters where safe, timestamp/context, raw/derived distinction and validation status. Do not publish sensitive target data, internal paths, operator details, exploit material or private evidence.

Failed, partial and negative results remain useful evidence when they explain coverage or a decision. Do not silently discard them if they have unique diagnostic value.

## Tooling and local environment

Tool availability must be verified rather than inferred from PATH alone. Installations, downloads, caches, generated artifacts, processes and residues introduced by project work must be attributable and cleaned when safe. Do not remove pre-existing user data or tools as project cleanup.

## Vulnerability and incident handling

Potential vulnerabilities in Surface_Recon itself, accidental disclosure, credential exposure, unsafe execution, scope escape or evidence-integrity failures are private findings until triaged. Record affected scope, evidence, containment/remediation, validation and residual risk.

If a credential is exposed, deleting it from the current tree is insufficient: rotate/revoke it and assess history, artifacts, logs and downstream copies.

## INTERNAL → PUBLIC

PUBLIC material is derived from INTERNAL through a sanitized candidate. Never copy INTERNAL Git ancestry into PUBLIC. Before promotion classify content as PUBLICABLE, MOVER A NOTION, SANITIZAR, ELIMINAR or INVESTIGAR and run the Public-Surface Gate. HUMAN QA remains required where reserved by governance.

## Claims

Internal tests and gates demonstrate only the checks actually performed. They do not constitute certification, authorization for third-party testing, or proof that Surface_Recon discovers every attack surface.
