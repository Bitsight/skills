# Company Selection Guardrail

Use this before any findings, assets, or vulnerability report when the user gives a company name instead of a GUID.

## Why It Matters

Company names often match several Bitsight companies: parent ratings, subsidiaries, regional companies, self-published companies, bundles, shell companies, and similarly named businesses. A report is wrong if it queries a convenient match instead of the company that best represents the business the user meant. When the right company is unclear, ask the user to clarify before reporting issues.

## Required Workflow

1. Search with details:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
```

2. Inspect candidates for `details.in_portfolio`, `details.self_published`, `details.has_company_tree`, `details.primary_company`, `details.is_primary`, `details.confidence`, name, website, primary domain, and industry.
3. For any candidate with `has_company_tree=true`, or when a parent/subsidiary/self-published relationship could change the answer, inspect the tree:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid GUID --expand confidence,is_shell
```

4. If you need to find a named business, domain, or IP inside the tree, filter the visible tree GUIDs:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid GUID --guids-only --tree-name "Example"
```

5. Only proceed with findings/assets/vulnerabilities after selecting the GUID that best represents the business scope. Reuse that GUID for every follow-up query.

## Selection Rules

- Prefer the company that matches the user's requested business scope, not automatically the first search result.
- Prefer `in_portfolio=true` only when it also matches the intended business. Portfolio status is a useful signal, not proof.
- Treat `self_published` as meaningful. If the user asks about a self-published business, or the self-published company is the most accurate representation, select it even if another parent or similarly named company appears higher.
- Use `primary_company` and `is_primary` to understand whether a search hit is an anchor, a primary rating, or a child. Querying the parent tree may be appropriate for enterprise-wide questions; querying the child may be appropriate for a specific subsidiary or self-published company.
- Do not turn findings from the wrong company into "issues." If a result looks surprising, verify the company tree before interpreting it as risk. Honeypot-like findings on a mismatched company should be treated as a company-selection warning, not as remediation guidance.

## Domain-Scoped Questions

When the user asks about a specific domain or hostname (e.g. "certificates for www.example.com", "findings on login.example.com"), bootstrap company selection by searching on the domain rather than the company name:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "example.com" --company-domain
```

From the candidates, prefer the company whose `primary_domain` matches the queried domain. For large companies this is often the parent/group company (e.g. Example Group has `primary_domain=example.com`) rather than a regional subsidiary or self-published child, even if the child appears in the portfolio. The group company's findings cover the full IP/hostname space attributed to the domain.

## Ask For Clarification

Ask the user to choose when:

- Multiple plausible companies remain after checking search details and the tree.
- The choice is between a parent/root and a child/subsidiary/self-published company and the prompt does not state scope.
- The available candidates differ materially in portfolio status, self-published status, primary company, domain, industry, or tree position.
- You cannot verify the company tree due to permissions or API errors.

Include the short candidate list with names, GUIDs, domains/websites, and the relevant signals that make the choice ambiguous.
