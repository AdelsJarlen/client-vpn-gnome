# Security model

## Trust boundaries

| Component | Runs as | Trusts |
|---|---|---|
| `client-vpnd` | root, systemd-sandboxed | nothing from D-Bus callers without validation and polkit |
| `openvpn` phase 1 | `client-vpn` from the start | only the server (TLS, CA, `verify-x509-name`) |
| `openvpn` phase 2 | root while creating the tun device and routes, then `client-vpn` | same as above |
| App / SAML listener | the logged-in user | the browser POST, which the daemon re-validates |
| Shell extension | the logged-in user | read-only D-Bus properties; actions go through the app |

## Changes compared to upstream aws-vpn-client

| Upstream issue | Mitigation here |
|---|---|
| Pinned to OpenVPN 2.6.12, missing later security fixes | Patch ported to **2.7.8**. The RPM verifies the upstream tarball's GPG signature against a pinned key and applies the patch with `--fuzz=0`. |
| `sudo bash -c "<interpolated string>"` running OpenVPN as root with `--script-security 2` | No shell anywhere: `exec` with fixed argv. sudo is replaced by a polkit-gated D-Bus service. OpenVPN uses `--script-security 1` and `--user client-vpn`, and runs inside a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, capability bounding set, syscall filter). |
| SAML listener accepted any POST, unbounded, and kept running | The listener only exists during a login and accepts exactly one well-formed `POST /` (form type, ≤ 512 KB). The daemon then checks the response: base64 → strict XML, root `samlp:Response`, `Destination` = our ACS, `InResponseTo` = the ID of *our* AuthnRequest. Only the D-Bus client that started the login can complete it, and only once. |
| SAML token written to `./saml-response.txt` and put in argv | The token travels app → D-Bus → daemon → OpenVPN **management socket** (root-only directory, `--management-client-user root`). It is never written to disk, never in argv/env, and is redacted from logs. The daemon drops its copy after sending it. |
| Plain `dig` lookup, hard-coded port/proto | Go resolver with a `crypto/rand` hostname prefix. Port and protocol come from the profile. Server identity rests on the profile's `<ca>`, `remote-cert-tls server` and `verify-x509-name`, which are **required**. |
| AWS patch defines enlarged sizes without parentheses (`#define USER_PASS_LEN 1 << 17`), so `OPTION_PARM_SIZE + 16` becomes `1 << 33` (undefined behaviour) and `USER_PASS_LEN - 1` becomes `1 << 16` | All four size macros are parenthesized in `patches/openvpn-v2.7.8-aws.patch`. The build is free of `-Wshift-count-overflow`/`-Wparentheses` warnings. |
| Optional OpenSSL patch weakening self-signed certificate detection | Dropped. The build links against Fedora's system OpenSSL. |
| `.ovpn` could contain `up`, `plugin`, `script-security`, … executed as root | The profile sanitizer is an **allowlist**. Any script, plugin, management, file-path or include directive is rejected on import and checked again before every connection. |

## Known limitations

- If an IdP flow carries no `SAMLRequest` in the login URL, `InResponseTo` cannot be checked (the daemon logs a
  warning). The `Destination` check and the one-shot, caller-bound login still apply.
- The IdP's signature on the SAML assertion is verified by AWS, not by this client.
- The loopback port 35001 is fixed by AWS. Another local process could bind it first. The app then reports
  "port busy" instead of continuing.
- DNS settings pushed by the server are applied per link via systemd-resolved and disappear with the tun device.
- The bundled OpenVPN is on the **2.7** series. AWS only published a patch for 2.6.12. The 2.7 port makes the same
  changes, and also lifts 2.7's new 16-bit cap in `write_string()` (otherwise SAML passwords over 64 KiB would be
  rejected). Data channel offload (kernel `ovpn` module) is disabled unless `client-vpnd -dco` is used. (The official
  AWS client 6.x embeds OpenVPN 3 Core instead of 2.x.)
- The official client also handles AWS extensions pushed as `CRV1::` echoes (device posture checks, banners,
  client route monitoring). This client ignores them, so endpoints that *require* device posture checks will
  not work.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting:
<https://github.com/AdelsJarlen/client-vpn-gnome/security/advisories/new> (Security tab → *Report a
vulnerability*). Please don't open public issues for security problems.

Include the version (`rpm -q client-vpn-gnome`), what an attacker needs (local user, network position,
malicious profile, …) and, if possible, a reproduction. Strip hostnames, addresses and tokens from logs.

## Supported versions

Only the latest release receives fixes. Security releases of the bundled OpenVPN are picked up by
rebuilding with `make openvpn-bump` (see README).
