# Maintained egress fork (source candidate)

Base: official sing-box v1.14.4, commit `c005f35300ce76427dc285481ec5695f5b179cd2`.
The publication PR is not a deployment or qualification approval.
This source candidate is not an upstream release or deployment.
The infrastructure project's current candidate remains stock v1.14.2 plus its
reviewed ECH patch until a separately approved source/pin/renderer update.

Custom contracts: `tls_ech: true` matches only extension presence in a sniffed
TCP TLS ClientHello (including GREASE). It neither decrypts ECH nor proves a
hostname/IP binding. A `sniff` action and default reject are separate policy
requirements; QUIC and direct/IPv6 bypass require independent denial.
`send_original_destination: true` on an HTTP outbound sends exactly one
`X-Infra-Original-Destination: IPv4:443` CONNECT header from the inbound
`OriginDestination`. Invalid/missing/non-TCP origins fail before dialing;
static header collisions fail at configuration construction. It defaults false.
The destination used for CONNECT may be overridden to a name while the
original intercepted IP is kept separately from the routing override. This
metadata is not cryptographically authenticated. Only verified central mTLS identity,
not this header, establishes relay identity. The production renderer must
require TLS and verified mTLS before enabling this option; never enable it for
an untrusted proxy.

The maintained `release/egress` line is based on an official stable tag;
upstream prerelease `main` and the existing ECH branch remain untouched.
After independent review and publication, the fork's exact reviewed commit
archive and its hashes become infra's canonical relay source. Infra retires its
independently maintained ECH patch in the separately approved transition; no
exported patch copy is a parallel long-term source. No generic upstream binary
auto-update may replace this fork or bypass the paired central wire contract.
For `1.14.4-local-egress1`, that contract is a single
`X-Infra-Original-Destination` IPv4:443 value on a TCP CONNECT to the routed
name, accepted only from an authenticated relay under the separately reviewed
central policy. Change the relay and central contract versions together; the
header alone never grants authorization or proves the IP/name binding.

To refresh: select an official stable tag; compare the upstream sniffer, rule
schema, HTTP outbound, redirect original-destination and module graph; port the
small local changes over that tag without replacing upstream behavior. Review
advisory fixed ranges and dependent minimums rather than running `go get -u`.
The declared inputs are in `release/EGRESS_BUILD_INPUTS`; run
`bash release/egress-check.sh /new/output/directory` with its exact Go and
govulncheck versions on PATH (and Python 3). The gate runs focused and race tests,
verifies modules, records a content manifest of tracked and non-ignored untracked
working-tree inputs (including dirty content and symlink targets), checks for
drift after each stage, and builds
production-tagged Linux amd64 and arm64 binaries, and rejects binary scanner
findings or scanner failures. All uploaded receipts, including the complete
source manifest, module verification, both build logs, and scanner database
source/updated time are hashed in SHA256SUMS. The default DB is explicitly
https://vuln.go.dev; EGRESS_VULN_DB selects a labelled custom DB instead.
The output directory must not exist beforehand; the gate uses GOWORK=off and
read-only module commands, refusing source drift (including go.sum changes).
CI runs native amd64 tests and cross-builds
arm64; neither this nor local ARM64 runtime checks prove native tests on both
arches. CI only records bounded artifacts; it has no deployment or publishing
permission. No schedule/Dependabot activation is claimed: GitHub's scheduled
and Dependabot configuration must live on the default branch, which is
intentionally untouched. Manual stable-tag review and PR checks are required.

Change inputs together: stable base tag, reviewed source diff and dependency
graph, Go/scanner pins, build tags, explicit custom version, paired central
contract version, renderer pin and hashes. Review changed dependencies and
security advisories, not just passing tests; the unlinked x/crypto/openpgp
advisory is not fixed or waived. Record the source archive/commit, module
inventory, checksums, tests and vulnerability receipts before infra consumes
the new version. Rollback requires a previously accepted paired relay/central
version and restrictive firewall state, followed by real allow/deny checks;
never restore direct or IPv6 fallback. Native firewall, mTLS/IP-to-name binding,
QUIC/direct denial, restart/rollback and site acceptance remain pending infra
qualification gates, not results of these source-only tests.
