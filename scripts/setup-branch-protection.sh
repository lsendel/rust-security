#!/usr/bin/env bash
set -euo pipefail

# Configure branch protection with required status checks via GitHub REST API v3.
# Usage: GITHUB_TOKEN=... scripts/setup-branch-protection.sh <owner> <repo> <branch>

if [[ ${#} -lt 3 ]]; then
  echo "Usage: GITHUB_TOKEN=... $0 <owner> <repo> <branch>" >&2
  exit 1
fi

OWNER=$1
REPO=$2
BRANCH=$3

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Error: GITHUB_TOKEN is not set" >&2
  exit 1
fi

API=https://api.github.com

# Required checks contexts — update if you rename workflows/jobs
read -r -d '' CONTEXTS_JSON << 'JSON' || true
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "CI",
      "Frontend CI",
      "CI - Lint & Clippy",
      "Documentation Testing",
      "Fast PR Checks"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null
}
JSON

echo "Configuring branch protection for ${OWNER}/${REPO}@${BRANCH}..."

curl -sS -X PUT \
  -H "Authorization: token ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${API}/repos/${OWNER}/${REPO}/branches/${BRANCH}/protection" \
  -d "${CONTEXTS_JSON}" | jq '.required_status_checks.contexts' || true

echo "Done. Verify settings in repository Branch protection rules."

