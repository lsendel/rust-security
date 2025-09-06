# Branch Protection and Required Checks

This guide helps configure GitHub branch protection and required status checks aligned with our streamlined CI.

## Recommended Protection Rules (main)

- Require pull request reviews: 1+
- Require review from Code Owners: enabled (recommended)
- Require status checks to pass before merging: enabled
- Require branches to be up to date before merging: enabled
- Include administrators: optional
- Restrict who can push to matching branches: optional

## Required Status Checks (PRs to main)

Enable these checks in Branch protection → "Require status checks":

- CI
- Frontend CI
- CI - Lint & Clippy
- Documentation Testing (optional but recommended)
- Fast PR Checks (optional for speed)

Notes:
- Heavy security/performance/compliance workflows do not run on PRs anymore (push/schedule only), so they should not be marked as required for PRs.

## Configure via GitHub UI

1. Settings → Branches → Add rule → Branch name pattern: `main`
2. Toggle required checks listed above.
3. Save. Repeat for `develop` if desired.

## Configure via API (script)

Use `scripts/setup-branch-protection.sh` with a token that has `repo` scope.

Example:

```
export GITHUB_TOKEN=ghp_xxx
scripts/setup-branch-protection.sh owner repo main
```

The script sets the required checks to the list above. Adjust inside the script if you rename workflows.

## CODEOWNERS (optional)

Add `.github/CODEOWNERS` to require targeted reviews. Example template:

```
# Path-based ownership (replace with actual teams or users)
*.rs          @your-org/rust-core
user-portal/  @your-org/frontend
.github/      @your-org/devops
```

Commit with real teams/usernames to avoid blocking merges.
