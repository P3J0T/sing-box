#!/usr/bin/env bash
# Focused, nonprivileged egress candidate gate. Output directory is mandatory.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source release/EGRESS_BUILD_INPUTS
if [[ $# != 1 || -z $1 ]]; then echo 'usage: release/egress-check.sh OUTPUT_DIRECTORY' >&2; exit 2; fi
output=$1
if [[ $output != /* ]]; then echo 'output directory must be absolute' >&2; exit 2; fi
parent=$(realpath "$(dirname "$output")")
if [[ $parent == "$PWD" || $parent == "$PWD/"* ]]; then echo 'output must be outside the repository' >&2; exit 2; fi
if [[ -e $output || -L $output ]]; then echo 'output directory must not exist' >&2; exit 2; fi
[[ $GO_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && $GOVULNCHECK_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $EGRESS_VERSION =~ ^[a-zA-Z0-9][a-zA-Z0-9.+-]*$ ]] || { echo 'invalid declared build input' >&2; exit 2; }
command -v go >/dev/null || { echo 'go missing' >&2; exit 2; }
command -v govulncheck >/dev/null || { echo 'govulncheck missing' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 missing' >&2; exit 2; }
export GOTOOLCHAIN=local GOWORK=off
[[ $(go version) == "go version go${GO_VERSION} "* ]] || { echo 'wrong Go version' >&2; exit 2; }
# Explicit -db on both version inspection and scans makes inherited GOVULNDB
# incapable of silently replacing the default. A custom DB is labelled.
db=${EGRESS_VULN_DB:-https://vuln.go.dev}
if [[ -n ${EGRESS_VULN_DB:-} ]]; then db_kind=custom; else db_kind=default; fi
unset GOVULNDB
govulncheck -db "$db" -version | grep -Fxq "Scanner: govulncheck@${GOVULNCHECK_VERSION}" || { echo 'wrong govulncheck version' >&2; exit 2; }
mkdir -p "$output"
output=$(cd "$output" && pwd)
{
  printf 'db_kind=%s\ndb_requested=%s\n' "$db_kind" "$db"
  govulncheck -db "$db" -version
} > "$output/scanner-info.txt"
grep -Fxq "Scanner: govulncheck@${GOVULNCHECK_VERSION}" "$output/scanner-info.txt"
grep -q '^DB:' "$output/scanner-info.txt"
grep -q '^DB updated:' "$output/scanner-info.txt"
source_digest=$(python3 release/source_manifest.py capture "$output/source-manifest.json")
verify_source() {
  python3 release/source_manifest.py verify "$output/source-manifest.json" >/dev/null || {
    echo 'source/input drift: release receipts are invalid' >&2
    exit 1
  }
}
{
  printf 'version=%s\ngo=%s\nscanner=%s\n' "$EGRESS_VERSION" "$(go version)" "$(grep '^Scanner:' "$output/scanner-info.txt")"
  printf 'commit=%s\n' "$(git rev-parse HEAD)"
  printf 'source_digest=%s\n' "$source_digest"
  if [[ -z $(git status --porcelain=v1 --untracked-files=all) ]]; then
    echo 'source_state=clean'
  else
    echo 'source_state=dirty'
    git status --porcelain=v1 --untracked-files=all
  fi
  printf 'tags=%s\n' "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)"
  printf 'ldflags=%s\n' "$(cat release/LDFLAGS)"
} > "$output/provenance.txt"
sha256sum go.mod go.sum release/EGRESS_BUILD_INPUTS release/DEFAULT_BUILD_TAGS_OTHERS release/LDFLAGS > "$output/input-sha256.txt"
verify_source
go mod verify > "$output/module-verification.txt"
verify_source
go list -mod=readonly -m all > "$output/modules.txt"
verify_source
packages=(./common/sniff ./route/rule ./protocol/http ./option)
go test -mod=readonly -count=1 "${packages[@]}" > "$output/focused-tests.txt" 2>&1
verify_source
go test -mod=readonly -race -count=1 -run 'TestOriginalDestination|TestTLSECH' "${packages[@]}" > "$output/race-tests.txt" 2>&1
verify_source
tags=$(cat release/DEFAULT_BUILD_TAGS_OTHERS)
ldflags="-X github.com/sagernet/sing-box/constant.Version=${EGRESS_VERSION} $(cat release/LDFLAGS) -s -w -buildid="
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false -tags "$tags" -ldflags "$ldflags" -o "$output/sing-box-linux-$arch" ./cmd/sing-box > "$output/build-$arch.txt" 2>&1
  verify_source
done
for arch in amd64 arm64; do
  # Text mode exits nonzero for reachable findings and scanner/DB failures.
  # Never reinterpret JSON exit 0 as zero findings.
  govulncheck -db "$db" -format=text -mode=binary "$output/sing-box-linux-$arch" > "$output/vulnerability-$arch.txt" 2>&1
  verify_source
done
printf 'source_digest_post=%s\n' "$(python3 release/source_manifest.py verify "$output/source-manifest.json")" > "$output/source-state-post.txt"
verify_source
(cd "$output" && sha256sum sing-box-linux-amd64 sing-box-linux-arm64 source-manifest.json source-state-post.txt scanner-info.txt modules.txt input-sha256.txt provenance.txt module-verification.txt focused-tests.txt race-tests.txt build-amd64.txt build-arm64.txt vulnerability-amd64.txt vulnerability-arm64.txt > SHA256SUMS)
