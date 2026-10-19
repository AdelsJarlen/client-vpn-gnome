# Client VPN for GNOME

> **Unofficial.** This project is not affiliated with, endorsed by or supported by Amazon Web Services.
> AWS and AWS Client VPN are trademarks of Amazon.com, Inc. or its affiliates. AWS supports SAML sign-in
> only with its own client, so a change on AWS's side can break this client without notice.

Connect to [AWS Client VPN](https://aws.amazon.com/vpn/client-vpn/) endpoints that use **SAML federated
authentication** from Fedora and GNOME. AWS's own Linux client is published only for Ubuntu.

- **client-vpnd**: a small Go system service (D-Bus activated, polkit-authorized) that drives a patched
  OpenVPN 2.7.8 and drops privileges once the tunnel is up.
- **Client VPN** app: GTK 4 / libadwaita (Python). It imports your `.ovpn` profile, runs the browser
  login and shows status.
- **Quick Settings toggle**: a GNOME Shell extension showing connection state, tunnel address, uptime
  and traffic.

Based on [aws-vpn-client](https://github.com/aws-vpn-client/aws-vpn-client) by Alex Samorukov. See
[SECURITY.md](SECURITY.md) for what was changed and why.

## Compatibility

| Area | Status |
|---|---|
| Fedora 44, GNOME Shell 50 (Wayland) | **Tested** |
| SAML federated authentication, UDP endpoint, split tunnel | **Tested** against a production endpoint |
| OpenVPN 2.7.8 with the userspace data path | **Tested** (default) |
| Kernel data channel offload (`ovpn` module, `client-vpnd -dco`) | Untested, off by default |
| DNS servers/domains pushed by the endpoint (applied via systemd-resolved) | Implemented, untested |
| Full tunnel (`redirect-gateway`) | Untested |
| TCP endpoints, IPv6 | Untested |
| Mutual certificate authentication combined with SAML | Untested |
| Active Directory / certificate-only authentication | Not supported (SAML only) |
| AWS device posture assessment, banners, client route monitoring | **Not supported.** Endpoints that require posture checks will reject the connection |
| Other GNOME Shell versions | Not supported yet. The extension declares GNOME 50 only |
| Other distributions | RPM packaging only (COPR: Fedora 44 x86_64). The code is distribution-neutral but untested elsewhere |

Reports about other setups are very welcome (see [Reporting problems](#reporting-problems)).

## How it works

AWS Client VPN carries SAML through the OpenVPN dynamic challenge (CRV1) protocol:

1. OpenVPN connects with password `ACS::35001`. The server rejects it with a `CRV1` challenge containing a
   session ID and the IdP login URL.
2. You log in in the browser. The IdP POSTs a `SAMLResponse` to `http://127.0.0.1:35001/`.
3. OpenVPN reconnects **to the same server IP** with password `CRV1::<session>::<SAMLResponse>`.

Stock OpenVPN cannot send a password that long, so the build carries the AWS patch
(`patches/openvpn-v2.7.8-aws.patch`, which only enlarges buffers and length fields).

```
 Quick Settings toggle ─┐                      system D-Bus
 Client VPN app ────────┼────────────────────> client-vpnd (root, sandboxed by systemd)
   └ one-shot listener 127.0.0.1:35001          ├ phase 1: openvpn as user `client-vpn`
                                                └ phase 2: openvpn, drops to `client-vpn` once up
```

## Install (Fedora 44)

Packages are built in Fedora COPR from this repository:

```sh
sudo dnf copr enable adelsjarlen/client-vpn-gnome
sudo dnf install client-vpn-gnome
gnome-extensions enable client-vpn@adelsjarlen.github.io   # then log out and back in
```

Updates, including rebuilds for OpenVPN security releases, then arrive through `dnf upgrade` and
GNOME Software. COPR signs the packages and publishes the source RPMs.

## Install from source (Fedora)

```sh
sudo dnf install golang rpm-build gnupg2 openssl-devel lzo-devel lz4-devel \
                 libnl3-devel libcap-ng-devel systemd-rpm-macros desktop-file-utils
make test
make rpm
sudo dnf install -y ./rpmbuild/RPMS/x86_64/client-vpn-gnome-*.rpm
gnome-extensions enable client-vpn@adelsjarlen.github.io   # then log out and back in
```

The RPM build checks the OpenVPN release tarball's signature against the pinned key in
`packaging/openvpn-signing-key.asc`, applies the patch with `--fuzz=0` and runs the tests.

**Upgrading from the old `awsvpn` package (≤ 0.2.0):** installing `client-vpn-gnome` replaces it and copies
your imported profile. Enable the renamed extension (`client-vpn@adelsjarlen.github.io`) and log in again.

## Usage

1. Open **Client VPN** and choose **Import Profile…**, then pick the `.ovpn` file from your administrator
   (this asks for your admin password once).
2. Click **Connect**, or use the **Client VPN** toggle in Quick Settings. Your browser opens; sign in.
3. The toggle shows *Connected*. Click it again to disconnect.

From a terminal: `client-vpn --connect` / `client-vpn --disconnect`. The daemon logs to
`journalctl -u client-vpnd`.

Any user logged in at the active local session may connect and disconnect without a password. Importing
or replacing the profile requires administrator authentication. On shared machines, tighten
`io.github.AdelsJarlen.ClientVpn.connect` with a polkit rule if needed.

## Keeping OpenVPN up to date

The package bundles its own patched OpenVPN (`/usr/libexec/client-vpn/openvpn`), so Fedora's OpenVPN
updates never touch it. A daily **user timer** (`client-vpn-update-check.timer`) compares the bundled
version with upstream release tags on GitHub. It only reports releases whose signed tarball is downloadable,
and lists any CVEs mentioned in the upstream ChangeLog. You can also check from the app menu (**Check for
OpenVPN Updates**) or with `client-vpn --check-updates`.

**Installed from COPR:** you don't need to do anything. You get one notification per OpenVPN release; the
rebuilt package then arrives through `dnf upgrade` / GNOME Software. If it hasn't arrived within two weeks,
please open an issue.

**Built from source (and maintainers):** a newer release in the same series gives a notification (repeated
weekly until you update) and a banner in the app with the rebuild steps:

```sh
make openvpn-bump V=2.7.9     # rebases the AWS patch (no fuzz), updates Makefile + spec, bumps Release
make rpm
sudo dnf upgrade -y ./rpmbuild/RPMS/x86_64/client-vpn-gnome-*.rpm
```

A new OpenVPN *series* is announced once to source builds, because it needs the AWS patch ported by hand.

**Privacy:** the update check contacts `api.github.com`, `raw.githubusercontent.com` and
`swupdate.openvpn.org` once a day. Nothing about you or your VPN is sent. To turn it off:
`systemctl --user disable --now client-vpn-update-check.timer`.

## Reporting problems

Open an issue with your distribution, GNOME version and the output of
`journalctl -u client-vpnd -b`. The daemon redacts SAML session IDs, login URLs and tokens, but
**check the log for your own hostnames and addresses before posting**.

Security issues: please report them privately, see [SECURITY.md](SECURITY.md).

## Maintenance automation

`.github/workflows/maintenance.yml` runs `scripts/maintenance_check.py` on a schedule and opens issues
labelled `maintenance`:

- **Weekly:** as soon as a newer OpenVPN release (with a downloadable signed tarball) exists in the bundled
  series, an issue with the rebuild steps, labelled `security` if the ChangeLog names CVEs. A new OpenVPN
  series gets a separate issue.
- **Quarterly:** a `Maintenance check <year>-Q<n>` checklist covering GNOME Shell versions against the
  extension, active Fedora releases against the COPR build targets, the last COPR build, CI, Dependabot PRs,
  open issues and a reminder to read AWS's client release notes.

Run either by hand from the Actions tab (*Maintenance → Run workflow*), or locally with
`GITHUB_TOKEN=$(gh auth token) scripts/maintenance_check.py --mode quarterly --dry-run`.
GitHub disables scheduled workflows in public repositories after 60 days without repository activity, and
emails a warning first. Re-enable it from the Actions tab if that happens.

## Development

```sh
make test                                       # gofmt, go vet, go test -race, python tests
busctl --system introspect io.github.AdelsJarlen.ClientVpn1 /io/github/AdelsJarlen/ClientVpn1
```

To extract the patch from a newer AWS source drop, see `scripts/extract-aws-patch.sh`.

## License

MIT for this project (see [LICENSE](LICENSE)), including the original work by Alex Samorukov.

The RPM also contains a patched OpenVPN binary, which is licensed GPL-2.0 with the OpenSSL exception.
Its complete source (the upstream release tarball plus `patches/`) is in this repository and in every
source RPM.
