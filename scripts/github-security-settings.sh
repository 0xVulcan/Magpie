#!/usr/bin/env bash
# One-time GitHub settings for the Security Gate. Run where `gh` is logged in as the repo owner.
#
#   scripts/github-security-settings.sh 0xVulcan/Magpie       # public: README + Releases
#   scripts/github-security-settings.sh 0xVulcan/magpie-src   # private: source
#
# Secret scanning, push protection, the main ruleset and private vulnerability reporting are free on public
# repos only; on a private repo (free plan) they are skipped, and the pre-commit hook + CI gate cover it.
set -euo pipefail
REPO=${1:?usage: $0 OWNER/REPO}
R=repos/$REPO
VIS=$(gh api "$R" -q .visibility)
echo "[*] $REPO is $VIS"

# Dependabot alerts and automatic security-fix pull requests
gh api -X PUT "$R/vulnerability-alerts"
gh api -X PUT "$R/automated-security-fixes"

# Workflow token read-only, and it cannot approve pull requests
gh api -X PUT "$R/actions/permissions/workflow" -F default_workflow_permissions=read -F can_approve_pull_request_reviews=false

# Only GitHub's own actions plus the two scanners, and every action must be pinned to a full commit SHA
gh api -X PUT "$R/actions/permissions" -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
gh api -X PUT "$R/actions/permissions/selected-actions" --input - <<'EOF'
{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["gitleaks/gitleaks-action@*","trufflesecurity/trufflehog@*"]}
EOF

# Hygiene: no wiki or projects, delete merged branches, no auto-merge
gh api -X PATCH "$R" -F has_wiki=false -F has_projects=false -F delete_branch_on_merge=true -F allow_auto_merge=false

if [ "$VIS" = public ]; then
  # Secret scanning + push protection: GitHub itself rejects pushes containing known secret formats
  gh api -X PATCH "$R" --input - <<'EOF'
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}
EOF
  # Protect main: no force push, no deletion (skip if it already exists)
  if ! gh api "$R/rulesets" -q '.[].name' | grep -qx protect-main; then
    gh api -X POST "$R/rulesets" --input - <<'EOF'
{"name":"protect-main","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}
EOF
  fi
  gh api -X PUT "$R/private-vulnerability-reporting"
else
  echo "[i] Private repo on the free plan: skipping secret scanning, push protection, rulesets, private vulnerability reporting."
fi

echo "[*] Read back:"
gh api "$R/actions/permissions"
gh api "$R/actions/permissions/selected-actions"
gh api "$R/actions/permissions/workflow"
gh api "$R" -q '{visibility,has_wiki,has_projects,delete_branch_on_merge,allow_auto_merge,security_and_analysis}'
