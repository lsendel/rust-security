use std::fs;
use std::path::Path;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Setting up enhanced Git hooks for compilation error prevention...");

    // Create .git/hooks directory if it doesn't exist
    let hooks_dir = Path::new(".git/hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(hooks_dir)?;
    }

    // Enhanced pre-commit hook
    let pre_commit_content = r#"#!/bin/bash
echo "🔍 Running pre-commit checks..."

# Quick compilation check (fast)
cargo check --workspace --quiet
if [ $? -ne 0 ]; then
    echo "❌ Compilation failed. Running auto-fix..."
    ./scripts/fix-compilation-errors.sh

    # Check again after auto-fix
    cargo check --workspace --quiet
    if [ $? -ne 0 ]; then
        echo "❌ Compilation still failed after auto-fix."
        echo "Run: cargo check --workspace"
        echo "Or run: ./scripts/fix-compilation-errors.sh manually"
        exit 1
    fi
    echo "✅ Compilation fixed automatically!"
fi

# Quick lint check (fast)
cargo clippy --workspace --quiet -- -D warnings 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Linting warnings found. Consider fixing:"
    echo "Run: cargo clippy --workspace --fix"
    # Don't block, just warn for now
fi

echo "✅ Pre-commit checks passed"
"#;

    // Write pre-commit hook
    let pre_commit_path = hooks_dir.join("pre-commit");
    fs::write(&pre_commit_path, pre_commit_content)?;
    set_executable(&pre_commit_path)?;

    // Enhanced pre-push hook
    let pre_push_content = r#"#!/bin/bash
echo "🚀 Running pre-push validation..."

# Run full test suite
cargo test --workspace --quiet
if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Please fix before pushing."
    exit 1
fi

# Security audit
cargo audit --quiet --deny warnings 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Security audit found issues. Consider updating dependencies."
    # Don't block for now, just warn
fi

echo "✅ Pre-push validation passed"
"#;

    // Write pre-push hook
    let pre_push_path = hooks_dir.join("pre-push");
    fs::write(&pre_push_path, pre_push_content)?;
    set_executable(&pre_push_path)?;

    // Commit message validation hook
    let commit_msg_content = r#"#!/bin/bash
# Validate commit message format
commit_msg_file="$1"

if [ ! -f "$commit_msg_file" ]; then
    echo "❌ Commit message file not found"
    exit 1
fi

commit_msg=$(cat "$commit_msg_file")

# Check for conventional commit format (optional for now)
# Uncomment to enforce:
# if ! echo "$commit_msg" | grep -qE "^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .{1,}"; then
#     echo "⚠️  Commit message doesn't follow conventional format"
#     echo "Expected: type(scope): description"
#     echo "Example: feat(auth): add login validation"
#     # Don't block for now
# fi

# Check for sensitive information
if echo "$commit_msg" | grep -q -i "password\|secret\|token\|key"; then
    echo "⚠️  Commit message may contain sensitive information"
    # Don't block, just warn
fi

echo "✅ Commit message validation passed"
"#;

    // Write commit-msg hook
    let commit_msg_path = hooks_dir.join("commit-msg");
    fs::write(&commit_msg_path, commit_msg_content)?;
    set_executable(&commit_msg_path)?;

    println!("✅ Enhanced Git hooks installed!");
    println!("📋 Installed hooks:");
    println!("   - pre-commit: Compilation and linting checks with auto-fix");
    println!("   - pre-push: Full test suite and security audit");
    println!("   - commit-msg: Message validation");

    Ok(())
}

fn set_executable(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}
