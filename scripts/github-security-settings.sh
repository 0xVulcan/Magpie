#!/usr/bin/env bash
# One-time GitHub settings for the Security Gate. Run from a machine where `gh` is logged in as the repo owner.
# 0xVulcan/Magpie is public, so secret scanning, push protection and the main ruleset are all free.
set -euo pipefail
R=repos/0xVulcan/Magpie

# Dependabot alerts and automatic security-fix pull requests
gh api -X PUT $R/vulnerability-alerts
gh api -X PUT $R/automated-security-fixes

# Workflow token read-only, and it cannot approve pull requests
gh api -X PUT $R/actions/permissions/workflow -F default_workflow_permissions=read -F can_approve_pull_request_reviews=false

# Only GitHub's own actions plus the two scanners, and every action must be pinned to a full commit SHA
gh api -X PUT $R/actions/permissions -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
gh api -X PUT $R/actions/permissions/selected-actions --input - <<'EOF'
{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["gitleaks/gitleaks-action@*","trufflesecurity/trufflehog@*"]}
EOF

# Secret scanning + push protection: GitHub itself rejects pushes containing known secret formats
gh api -X PATCH $R --input - <<'EOF'
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}
EOF

# Protect main: no force push, no deletion
gh api -X POST $R/rulesets --input - <<'EOF'
{"name":"protect-main","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}
EOF

# Private vulnerability reporting
gh api -X PUT $R/private-vulnerability-reporting

# Hygiene: no wiki or projects, delete merged branches, no auto-merge
gh api -X PATCH $R -F has_wiki=false -F has_projects=false -F delete_branch_on_merge=true -F allow_auto_merge=false

echo "Read back:"
gh api $R/actions/permissions
gh api $R/actions/permissions/selected-actions
gh api $R/actions/permissions/workflow
gh api $R -q '{visibility,has_wiki,has_projects,delete_branch_on_merge,allow_auto_merge,security_and_analysis}'
