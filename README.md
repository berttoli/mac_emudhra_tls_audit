# macOS eMudhra TLS Trust Audit

A read-only macOS diagnostic for the **October 2026 eMudhra / emSign intermediate certificate compromise**, plus a practical remediation and verification runbook.

> [!IMPORTANT]
> **TLS exposure is not evidence of a hacked Mac.** A successful connection to an affected test server shows that a particular client accepted that certificate chain. It does not establish that anyone intercepted your traffic or accessed your computer.
>
> This project is an independent diagnostic, **not an official Apple or eMudhra security tool**. It tests a subset of the affected chains and does not replace security updates or a full incident investigation.

**Last reviewed:** October 22, 2026  
**Target:** macOS, Bash 3.2 or later  
**Audit script:** [`mac_emudhra_tls_audit.sh`](./mac_emudhra_tls_audit.sh)

## Contents

- [Background](#background)
- [Quick start](#quick-start)
- [What the audit checks](#what-the-audit-checks)
- [Understanding the results](#understanding-the-results)
- [Findings from the initial investigation](#findings-from-the-initial-investigation)
- [Remediation](#remediation)
- [Re-test and validate](#re-test-and-validate)
- [Rollback a manual certificate-store change](#rollback-a-manual-certificate-store-change)
- [Limitations and troubleshooting](#limitations-and-troubleshooting)
- [References](#references)

## Background

In October 2026, the private keys associated with **eight eMudhra intermediate CA certificates** were found to be recoverable. Six of the affected intermediates could be used in TLS certificate chains. An attacker with network interception capability could potentially use an affected key to impersonate a HTTPS server to clients that still trust the chain.

Browser vendors issued certificate blocks, but not every command-line TLS client consumes browser or operating-system revocation information. In particular, some macOS utilities and separately installed tools use PEM CA bundles such as `/etc/ssl/cert.pem` or their own bundled certificate collections.

That means these are **separate questions**:

1. Is an affected root present in a local certificate bundle?
2. Does a specific client actually accept one of the affected intermediate chains?
3. Is there any evidence that an attacker exploited that exposure?

The audit helps with questions 1 and 2. **It cannot answer question 3.**

The public incident advisory and its test hosts are maintained at [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/).

## Quick start

Place `README.md` and `mac_emudhra_tls_audit.sh` in the same directory. No dependency installation or administrator privileges are required to run the audit.

### 1. Check the script before execution

```bash
bash -n ./mac_emudhra_tls_audit.sh
```

The command should finish without output if the Bash syntax is valid. This is a **syntax check**, not a security audit of the script.

### 2. Run a local, offline inventory

```bash
bash ./mac_emudhra_tls_audit.sh --offline \
  2>&1 | tee ./emudhra-offline.log
```

Checks local certificate bundles, selected TLS environment variables, Git's global `sslVerify` setting, and Python packaging versions. No test-host connections are made.

### 3. Run the live validation probes

```bash
bash ./mac_emudhra_tls_audit.sh --online \
  2>&1 | tee ./emudhra-online.log
```

This performs the inventory and attempts HTTPS handshakes to two published incident test hosts using available Apple curl, Homebrew curl, and the selected `python3` interpreter.

To **skip the inventory** and test only TLS behavior:

```bash
bash ./mac_emudhra_tls_audit.sh --probe-only
```

> [!NOTE]
> The online probes connect to a public incident-checking service. Its operators report collecting aggregate successful-connection counts and user-agent information. Use `--offline` if public probes are not acceptable in your environment.

## What the audit checks

| Check | Coverage | Important caveat |
| --- | --- | --- |
| macOS and tooling | Reports paths to `curl`, `git`, `python3`, `pip3`, `uv`, and OpenSSL | Identifying a binary is not validating its TLS behavior |
| Local CA bundles | Counts PEM certificates and looks for affected-root section headings | Certificate names alone do not prove trust or exploitation |
| TLS configuration | Inspects selected certificate overrides and Git's global `http.sslVerify` | Does **not** evaluate every repository, system, or per-process Git override |
| Apple curl | Live TLS handshake using `/usr/bin/curl` | Tests two representative affected chains |
| Homebrew curl | Live TLS handshake when the expected binary exists | The active `curl` on `PATH` may be different |
| Python TLS | Tests `ssl.create_default_context()` for the selected `python3` | Does not automatically test `requests`, `pip`, every interpreter, or every virtual environment |
| Python packaging | Reports selected `pip` and `certifi` versions | A patched Python TLS test does not prove pip's bundled CA data is patched |
| Git | Checks global TLS verification configuration | **No live Git HTTPS verification is performed** |

## Understanding the results

| Result | Meaning | Action |
| --- | --- | --- |
| `[EXPOSED]` | The client successfully validated and connected to a test host serving an affected chain | Treat as an actionable TLS exposure |
| `[BLOCKED]` | The client rejected that test chain due to certificate verification | Good result **for that client and that chain** |
| `[WARN]` | Configuration or CA inventory warrants review | Investigate; it is not proof of compromise |
| `[UNKNOWN]` | Connection failed for an unrelated reason, or the test could not complete | Diagnose connectivity and retry |
| `[INFO]` | Inventory or context | Informational only |

The script's **process exit status** is separate from the curl test exit codes:

- `2`: At least one exposure was detected.
- `1`: No confirmed exposure, but warnings or incomplete checks were found.
- `0`: No exposure or warnings were recorded by the checks that ran. **An offline-only `0` is not a clean bill of health.**

### Direct, unambiguous curl testing

Do not rely solely on `which curl`: Homebrew and Apple curl can behave differently. Invoke each explicitly.

```bash
for client in /usr/bin/curl /opt/homebrew/opt/curl/bin/curl; do
  [ -x "$client" ] || continue
  for host in \
    dv-g3b-emudhra.we-have-a-problem.com \
    dv-g3b-aaa-emudhra.we-have-a-problem.com; do
    "$client" -q --noproxy '*' --connect-timeout 6 --max-time 12 \
      -sS -o /dev/null "https://$host/"
    printf '%s | %s | exit=%s\n' "$client" "$host" "$?"
  done
done
```

**Interpreting curl's exit code:**

- `0`: The request succeeded, so the client **accepted** this incident test chain. This is the concerning outcome.
- `60` (and occasionally `51`): Certificate verification failure, which is the intended outcome for these test hosts.
- `6`, `7`, `28`, or other codes: DNS, connection, timeout, or another error. **Inconclusive**, not evidence of protection.

Do **not** use `-k`, `--insecure`, `GIT_SSL_NO_VERIFY=true`, or disable TLS verification to make these tests pass. `-q` suppresses curl's default config file; `--noproxy '*'` avoids configured HTTP proxies so the intended endpoint is tested directly.

## Findings from the initial investigation

These are a **historical snapshot from October 22, 2026**, not live results from everyone who downloads this repository.

| Component | Observed | Interpretation at time of investigation |
| --- | --- | --- |
| macOS | 26.6.2 | OS version alone does not establish CLI TLS protection |
| Apple `/usr/bin/curl` | Exit `0` from **both** published test hosts | **Exposure confirmed for these chains at that time** |
| Homebrew curl | Exit `60` reported after installing updated curl and CA packages | Affected chains rejected by the tested Homebrew client |
| `/etc/ssl/cert.pem` | 128 PEM certificates, including affected-root headings | Bundle required review; not yet confirmed modified in the supplied log |
| Homebrew CA bundles | 188 PEM certificates; affected headings absent | Encouraging inventory result, but client testing remains decisive |
| Python | Python.org framework Python 3.12.8, OpenSSL 3.0.15 | Different install from earlier Homebrew Python, requiring separate checks |
| `certifi` | 2025.07.09 | **Older than the affected-CA remediation release** |
| `pip` | 24.3.1 | **Older than the affected-CA remediation release** |
| Git | Global `http.sslVerify` not disabled | No live Git TLS test was performed |
| `uv` | Installed, version not captured | Patch status unknown |

**Do not describe the machine as "compromised" from these results.** The established finding is acceptance of risky TLS chains by one tested client. No interception, malware, stolen credential, or unauthorized access was demonstrated.

## Remediation

Use vendor updates where available. Apply privileged system certificate-store changes **only when needed and only after reviewing them**. Keep a record of before/after results.

### 1. Update Homebrew's curl and CA bundle

```bash
brew update
brew install curl ca-certificates
brew upgrade curl ca-certificates

/opt/homebrew/opt/curl/bin/curl --version
brew list --versions ca-certificates curl
```

On Intel Macs, Homebrew might use `/usr/local/opt/curl/bin/curl`; adjust the path accordingly.

Re-run both test hosts using the explicit Homebrew curl path. **Exit `60` is expected**. Updating Homebrew curl does **not** change what `/usr/bin/curl` trusts.

### 2. Check and, if necessary, fix Apple's system PEM bundle

The [incident advisory's macOS section](https://emudhra.we-have-a-problem.com/#macos-curl) documents a workaround for command-line clients that verify against `/etc/ssl/cert.pem` without checking revocation.

**First re-test `/usr/bin/curl`.** If both test hosts return certificate errors, do not edit the system file just because the certificate names appear in it.

If `/usr/bin/curl` still returns `0`, and you have confirmed no system update has resolved the problem, the following is an **opt-in, privileged workaround** based on the published advisory. It stages the replacement *before* touching the system file, requires exactly two PEM certificates to be removed, and creates a timestamped backup.

> [!WARNING]
> This temporarily removes trust in **entire root certificates**, including the widely used AAA Certificate Services root, not only the eight compromised intermediates. Unrelated legitimate services may be affected. Do not apply casually to an enterprise-managed Mac. Inspect the official advisory and the command first.

```bash
(
  set -e
  src=/etc/ssl/cert.pem
  temp=$(mktemp)
  trap 'rm -f "$temp"' EXIT

  awk '/^(###|===) /{skip=0}
       /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
       !skip' "$src" > "$temp"

  before=$(grep -c '^-----BEGIN CERTIFICATE-----' "$src")
  after=$(grep -c '^-----BEGIN CERTIFICATE-----' "$temp")
  printf 'Certificates: %s -> %s\n' "$before" "$after"

  if [ "$((before - after))" -ne 2 ]; then
    echo 'ABORT: Expected exactly two certificates to be removed.' >&2
    exit 1
  fi

  backup="${src}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  sudo cp -p "$src" "$backup"
  sudo tee "$src" < "$temp" > /dev/null
  echo "Backup saved: $backup"
  echo 'Re-test /usr/bin/curl against both incident hosts.'
)
```

For the initial inventory above, a correctly applied workaround would change the count from **128 to 126**. That count is only a sanity check. It is **not** proof that all applications are protected. Re-run the direct curl probes to verify behavior.

A later macOS update may regenerate the file. Verify again after OS updates.

### 3. Update Python packaging certificates

The initial environment reported:

```text
Python 3.12.8
pip 24.3.1
certifi 2025.07.09
```

The Python security announcement recommends these minimum versions:

| Package | Minimum fixed version |
| --- | --- |
| `certifi` | `2026.10.19` |
| `pip` | `26.2.2` |
| `uv` | `0.13.4` |

**Update `pip` using the SHA-256-pinned wheel from the Python packaging team's security announcement**, then use the updated pip to upgrade certifi. The hash protects the wheel's integrity even if an existing TLS client is vulnerable:

```bash
python3 -m pip install \
  'pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70'

python3 -m pip install --upgrade certifi
python3 -m pip --version
python3 -m pip show certifi
```

Run the same process for **each relevant Python installation and virtual environment**, checking interpreter and package paths as you go. Installing a new `certifi` into one Python does not update another Python, a locked project environment, or `pip`'s separately vendored CA bundle. Updating the interpreter itself to a maintained security release is also recommended.

For `uv`, see the Python advisory's recommendations for using the native system trust store during a secure bootstrap when appropriate:

```bash
UV_SYSTEM_CERTS=true uv self update
uv --version
```

Only use that bootstrap path when the selected **system trust validation is protected**. The option does not itself repair an outdated PEM bundle.

### 4. Re-check Git and other clients separately

```bash
git --version
git config --show-origin --get-regexp 'http\..*ssl|http\.sslVerify' || true
```

This reports some relevant Git settings, but **is not a complete Git TLS verification**. Git can use different TLS backends, CA files, configuration scopes, and per-repository overrides. Also review `requests`, Node.js, Java, Go, Ruby, Perl, containers, CI runners, dependency lockfiles, and coding-agent runtimes where relevant. Do not assume changing the default `curl` fixes embedded clients.

## Re-test and validate

1. Run `/usr/bin/curl` against **both** published hosts and require a certificate rejection.
2. Test Homebrew curl independently against both hosts.
3. Re-run `bash ./mac_emudhra_tls_audit.sh --online` and read the **individual client results**, not just the conclusion line.
4. Check the reported Python interpreter, `certifi`, `pip`, and `uv` versions against patched releases.
5. Confirm a normal trusted site still works with each client, for example:

   ```bash
   /usr/bin/curl -q --noproxy '*' --max-time 12 \
     -sS -o /dev/null https://www.python.org/
   echo "Normal-site exit code: $?"
   ```

6. Repeat checks after macOS, Homebrew, Python, or trust-store updates.

**Success criterion:** The incident test hosts fail *because of certificate validation* for the clients under review, while a known-good TLS connection succeeds. This does not imply all other clients or all affected certificate chains have been tested.

## Rollback a manual certificate-store change

If you applied the optional `/etc/ssl/cert.pem` workaround and encounter a legitimate TLS regression, inspect the available backups:

```bash
ls -l /etc/ssl/cert.pem.bak.*
```

After identifying the **specific backup created immediately before your change**, restore it using its complete path:

```bash
sudo cp -p /etc/ssl/cert.pem.bak.YYYYMMDDTHHMMSSZ /etc/ssl/cert.pem
```

Replace the placeholder with your real backup filename. **Restoring the original bundle may reintroduce the exposure** if Apple has not shipped a fix, so do not treat rollback as remediation. Re-test `/usr/bin/curl` and investigate another update or a narrower application-specific trust configuration.

## Limitations and troubleshooting

- **The audit cannot establish historical compromise.** It does not inspect packet captures, proxy logs, malware, EDR findings, credential use, or unauthorized system changes.
- **Two chains are not an exhaustive test.** The incident checker publishes additional certificates and chain data; this script focuses on two representative TLS endpoints.
- **A root name is not a fingerprint check.** The offline inventory looks at certificate-section headings. Its warnings are intentionally conservative.
- **Git is not live-tested.** The script only inspects a global setting, so per-repository and environment-specific configuration may be missed.
- **Python has multiple trust paths.** Python's `ssl` default path differs from `requests`, `certifi`, `pip`, some Python.org installers, Homebrew Python, and isolated virtual environments.
- **Network failures are inconclusive.** Corporate proxies, firewall rules, DNS failures, and timeouts may prevent a probe from reaching the host. Do not convert such failures into a pass.
- **The prior `v2` script had a Bash syntax error.** Use `v3`. Always run `bash -n` before using a downloaded local script.
- **Avoid publishing raw logs without review.** Even though the script avoids printing values of selected environment variables, logs can reveal your OS version, installed software, paths, and security posture.
- **Audit code is read-only, remediation is not.** The audit does not require `sudo`. Editing `/etc/ssl/cert.pem` is a separate manual action with system-wide consequences.

## References

- [Primary technical incident advisory and test hosts](https://emudhra.we-have-a-problem.com/)
- [macOS command-line trust-store workaround](https://emudhra.we-have-a-problem.com/#macos-curl)
- [Python packaging team's security announcement](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [Mozilla security response](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- [Cloudflare technical explanation](https://blog.cloudflare.com/emudhra-certificate-compromise/)

---

**Key takeaway:** *A client accepting a forged-chain test means its TLS verification needs remediation. It does not, by itself, mean the computer was breached.*
