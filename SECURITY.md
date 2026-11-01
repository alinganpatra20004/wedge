<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | yes |

Until 1.0, only the latest 0.x release receives fixes.

## Reporting a vulnerability

Please report security problems privately through GitHub:
**[Report a vulnerability](https://github.com/OpenEdge-Labs/wedge/security/advisories/new)**
(the repository's Security tab). Do not open a public issue or pull request
for a suspected vulnerability.

Please include:

- the wedge version (`wedge --version`) and operating system;
- the relevant configuration, with secrets removed;
- steps or a request that reproduces the problem, and what you expected;
- the impact as you understand it.

What to expect:

- an acknowledgement within 7 days;
- an assessment (severity using CVSS v3.1, affected versions) within 14 days;
- a fix, or a mitigation if a fix takes longer, as soon as practical, with a
  GitHub security advisory and a CVE where appropriate;
- credit in the advisory if you want it.

Please give us a reasonable time to release a fix before disclosing details
publicly; we aim for 90 days or less.

## Scope

In scope: the `wedge` binary, its default configuration, the packages,
installers and container image published on the
[releases page](https://github.com/OpenEdge-Labs/wedge/releases), and the
release pipeline. Out of scope: vulnerabilities in applications behind the
reverse proxy, configurations that disable documented safeguards (for
example `log_secrets = true` or `--allow-unprotected-path`), and denial of
service that needs more traffic than the configured limits allow.

## How wedge is checked

Each release passes cargo-audit, cargo-deny, Semgrep, clippy and the test
suite, and is fuzzed. The [threat model](docs/security/threat-model.md) lists
every threat considered and the test for each mitigation; the
[verification log](docs/security/verification.md) records the results of
each phase's security checks, including known limitations and residual
risks. No software is free of vulnerabilities; these checks reduce risk, they
do not remove it.

## Verifying downloads

Every release asset has a Sigstore signature (`<file>.sigstore.json`) and,
except the public key `wedge-release.asc`, is listed in `SHA256SUMS` and
has a GitHub build provenance attestation. (In v0.1.0 the MSI and
`SHA256SUMS` have no attestation; use the checksum and Sigstore signature
for them.)

```sh
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <file> --repo OpenEdge-Labs/wedge
cosign verify-blob <file> --bundle <file>.sigstore.json \
  --certificate-identity-regexp '^https://github.com/(OpenEdge-Labs|alinganpatra20004)/wedge/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The project moved from `alinganpatra20004/wedge` to `OpenEdge-Labs/wedge`
after 0.1.1, so 0.1.x signatures name the old repository; the identity
pattern above accepts both. GitHub does not show the 0.1.x build provenance
attestations under the new name; for those releases rely on `SHA256SUMS` and
the Sigstore signatures, which do not depend on GitHub.

Releases after 0.1.1 are signed with cosign 3, which writes the newer
Sigstore bundle format. Cosign 3 verifies every release; with cosign 2.4 or
later, add `--new-bundle-format` to the command above for releases after
0.1.1.

From the release after 0.1.0, each release has a CycloneDX SBOM
(`wedge-<version>.cdx.json`), and the binaries embed their dependency list
(`cargo auditable`), so a downloaded binary can be checked directly:

```sh
cargo audit bin wedge
trivy rootfs wedge
```

The .deb and .rpm packages are also GPG-signed. The public key is
[`packaging/wedge-release.asc`](packaging/wedge-release.asc), fingerprint
`B84A 920D B6B5 11E6 46B1 24FD 983E F3CD D108 E023`:

```sh
sudo rpm --import wedge-release.asc && rpm -K wedge-*.rpm
```

The Windows installer will be Authenticode-signed once the project's
SignPath Foundation application is approved; until then Windows reports an
unknown publisher.
