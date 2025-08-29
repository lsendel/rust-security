# Formatting Guide - Preventing CI/CD Failures

## Problem We Solved

Previously, CI/CD failed due to inconsistent Rust code formatting. This happened because:
- Different developers used different rustfmt settings
- Code was committed without running `cargo fmt`
- No automated formatting enforcement was in place

## Solutions Implemented

### 1. Consistent rustfmt Configuration (`.rustfmt.toml`)

A project-wide rustfmt configuration ensures all developers use the same formatting rules:
- 100 character line width
- 4-space indentation
- Unix line endings
- Consistent import organization
- Trailing commas for vertical layouts

### 2. Git Pre-commit Hooks

**Setup**: Run `./setup-git-hooks.sh` once to install hooks

The pre-commit hook automatically:
- Runs `cargo fmt --all` on staged Rust files  
- Runs `cargo clippy` to catch issues
- Runs `cargo check` to ensure compilation
- Prevents commit if formatting/linting fails

**To bypass in emergencies**: `git commit --no-verify`

### 3. GitHub Actions Auto-formatting

**For Pull Requests**: The `Auto-format Code` workflow:
- Detects formatting issues in PRs
- Automatically commits proper formatting
- Comments on PR to notify developer
- Prevents merge until formatting is correct

**For Main Branch**: Format checks prevent improperly formatted code

### 4. IDE Integration Recommendations

**VS Code** (`.vscode/settings.json`):
```json
{
  "rust-analyzer.rustfmt.extraArgs": ["--config-path", ".rustfmt.toml"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

**IntelliJ Rust**:
- Enable "Rustfmt" in Settings → Languages → Rust → Rustfmt
- Enable "Format on Save" in Settings → Tools → Actions on Save

## Prevention Checklist

✅ **Before Committing**:
1. Run `cargo fmt --all` 
2. Run `cargo clippy --all-targets -- -D warnings`
3. Run `cargo check`
4. Let Git hooks do their job (don't use `--no-verify` unless emergency)

✅ **IDE Setup**:
1. Configure your IDE to use `.rustfmt.toml`
2. Enable format-on-save
3. Enable clippy integration

✅ **Team Process**:
1. New developers run `./setup-git-hooks.sh`  
2. PRs get auto-formatted by GitHub Actions
3. Main branch is protected with format checks

## Manual Commands

```bash
# Format all code
cargo fmt --all

# Check formatting without changing files
cargo fmt --all -- --check

# Run clippy with project settings
cargo clippy --all-targets --all-features -- -D warnings

# Full pre-commit check simulation
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo check
```

## Emergency Procedures

**If you need to commit urgently** (not recommended):
```bash
git commit --no-verify -m "emergency fix - formatting will be fixed later"
```

**Fix formatting after emergency commit**:
```bash
cargo fmt --all
git add -A
git commit -m "style: fix formatting after emergency commit"
```

## Troubleshooting

**Hook not running**: 
- Check `.githooks/pre-commit` is executable: `chmod +x .githooks/pre-commit`
- Verify Git config: `git config core.hooksPath .githooks`

**CI still failing**:  
- Pull latest changes: `git pull origin main`
- Run full format: `cargo fmt --all`
- Check `.rustfmt.toml` exists and is valid

**IDE not formatting**:
- Restart IDE after adding `.rustfmt.toml`
- Check IDE Rust plugin settings
- Verify `.rustfmt.toml` path in IDE config

## Benefits

- ✅ **No more formatting CI failures**
- ✅ **Consistent code style across team**  
- ✅ **Automated enforcement**
- ✅ **Developer-friendly (auto-fixes PRs)**
- ✅ **Emergency bypass available**
- ✅ **IDE integration supported**