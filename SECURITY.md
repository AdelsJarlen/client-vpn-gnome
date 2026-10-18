# Security model

## Trust boundaries

| Component | Runs as | Trusts |
|---|---|---|
| `awsvpnd` | root, systemd-sandboxed | nothing from D-Bus callers without validation and polkit |
| `openvpn` phase 1 | `awsvpn` from the start | only the server (TLS, CA, `verify-x509-name`) |
| `openvpn` phase 2 | root while creating the tun device and routes, then `awsvpn` | same as above |
| App / SAML listener | the logged-in user | the browser POST, which the daemon re-validates |
| Shell extension | the logged-in user | read-only D-Bus properties; actions go through the app |

## Changes compared to upstream aws-vpn-client

| Upstream issue | Mitigation here |
|---|---|
| Pinned to OpenVPN 2.6.12, missing later security fixes | Patch rebased onto **2.6.23**. The RPM verifies the upstream tarball's GPG signature against a pinned key and applies the patch with `--fuzz=0`. |
| `sudo bash -c "<interpolated string>"` running OpenVPN as root with `--script-security 2` | No shell anywhere: `exec` with fixed argv. sudo is replaced by a polkit-gated D-Bus service. OpenVPN uses `--script-security 1` and `--user awsvpn`, and runs inside a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, capability bounding set, syscall filter). |
| SAML listener accepted any POST, unbounded, and kept running | The listener only exists during a login and accepts exactly one well-formed `POST /` (form type, ≤ 512 KB). The daemon then checks the response: base64 → strict XML, root `samlp:Response`, `Destination` = our ACS, `InResponseTo` = the ID of *our* AuthnRequest. Only the D-Bus client that started the login can complete it, and only once. |
| SAML token written to `./saml-response.txt` and put in argv | The token travels app → D-Bus → daemon → OpenVPN **management socket** (root-only directory, `--management-client-user root`). It is never written to disk, never in argv/env, and is redacted from logs. The daemon drops its copy after sending it. |
| Plain `dig` lookup, hard-coded port/proto | Go resolver with a `crypto/rand` hostname prefix. Port and protocol come from the profile. Server identity rests on the profile's `<ca>`, `remote-cert-tls server` and `verify-x509-name`, which are **required**. |
| Optional OpenSSL patch weakening self-signed certificate detection | Dropped. The build links against Fedora's system OpenSSL. |
| `.ovpn` could contain `up`, `plugin`, `script-security`, … executed as root | The profile sanitizer is an **allowlist**. Any script, plugin, management, file-path or include directive is rejected on import and checked again before every connection. |

## Known limitations

- If an IdP flow carries no `SAMLRequest` in the login URL, `InResponseTo` cannot be checked (the daemon logs a
  warning). The `Destination` check and the one-shot, caller-bound login still apply.
- The IdP's signature on the SAML assertion is verified by AWS, not by this client.
- The loopback port 35001 is fixed by AWS. Another local process could bind it first. The app then reports
  "port busy" instead of continuing.
- DNS settings pushed by the server are applied per link via systemd-resolved and disappear with the tun device.

## Reporting

This is a private project. Open an issue in the repository.
