#!/usr/bin/env bash
# Pre-release audit: fails if a database, env file, signing file or release binary is tracked, if gitleaks finds
# a secret, or if any line matches a canary list kept OUTSIDE the repository (CANARY_FILE=/path/to/list).
# It holds no personal identifiers itself: a list of them in a public repo would be the leak.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "[*] Checking git index for forbidden file types..."
FORBIDDEN_FILES=$(git ls-files | grep -Ei '\.(db|sqlite|sqlite3|pcap|pcapng|har|log|pem|key|p8|p12|pfx|cer|mobileprovision|provisionprofile|dmg|pkg|exe|ipa|xpi|crx)$|(^|/)\.env(\.|$)|(^|/)data/|(^|/)(build|dist)/' | grep -v '^\.env\.example$' || true)
if [ -n "$FORBIDDEN_FILES" ]; then
  echo "[!] ERROR: Sensitive, database or build files are tracked in git:"
  echo "$FORBIDDEN_FILES"
  exit 1
fi

echo "[*] Checking .env.example holds placeholders only..."
if [ -f .env.example ]; then
  # Any value longer than 16 characters that is not an obvious placeholder is treated as a real secret.
  SUSPECT=$(grep -Ev '^\s*(#|$)' .env.example \
    | awk -F= '{k=$1; $1=""; v=substr($0,2); gsub(/["'\'' ]/,"",v)} length(v) > 16 && v !~ /YOUR_|_HERE|0000-0000|example|localhost|changeme/ {print k}' || true)
  if [ -n "$SUSPECT" ]; then
    echo "[!] ERROR: .env.example has long non-placeholder values for:"
    echo "$SUSPECT"
    exit 1
  fi
fi

echo "[*] Running Gitleaks on exactly what git tracks (index export) and on the commit history..."
if command -v gitleaks >/dev/null 2>&1; then
  # Scanning the working tree would also read ignored folders (data/ holds the real library), so scan a copy of
  # the git index instead: the files that would be published.
  EXPORT=$(mktemp -d)
  trap 'rm -rf "$EXPORT"' EXIT
  git checkout-index -a --prefix="$EXPORT/"
  gitleaks detect --no-git --no-banner -v -c .gitleaks.toml -s "$EXPORT"
  if git rev-parse --verify -q HEAD >/dev/null; then gitleaks detect --no-banner -v -c .gitleaks.toml -s .; fi
else
  echo "[!] WARNING: gitleaks not installed locally (brew install gitleaks)."
fi

if [ -n "${CANARY_FILE:-}" ] && [ -f "$CANARY_FILE" ]; then
  echo "[*] Scanning tracked files against external canary file: $CANARY_FILE"
  if git ls-files -z | xargs -0 rg -i -n -f "$CANARY_FILE" --; then
    echo "[!] ERROR: Canary match found!"
    exit 1
  fi
  if git ls-files | rg -i -f "$CANARY_FILE"; then
    echo "[!] ERROR: Canary match in a file name!"
    exit 1
  fi
fi

echo "[+] Audit passed successfully."
