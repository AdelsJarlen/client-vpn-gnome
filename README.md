# AWS VPN for GNOME

Connect to [AWS Client VPN](https://aws.amazon.com/vpn/client-vpn/) endpoints that use **SAML federated
authentication** from Fedora / GNOME, without the closed-source Ubuntu-only AWS client.

- **awsvpnd**: a small Go system service (D-Bus activated, polkit-authorized) that drives a patched
  OpenVPN 2.6.23 and drops privileges once the tunnel is up.
- **AWS VPN** app: GTK 4 / libadwaita (Python). It imports your `.ovpn` profile, runs the browser login and shows status.
- **Quick Settings toggle**: GNOME Shell 50 extension showing connection state, tunnel address, uptime and traffic.

Based on [aws-vpn-client](https://github.com/aws-vpn-client/aws-vpn-client) by Alex Samorukov. See
[SECURITY.md](SECURITY.md) for what was changed and why.

## How it works

AWS Client VPN uses the OpenVPN dynamic challenge (CRV1) protocol to carry SAML:

1. OpenVPN connects with password `ACS::35001`. The server rejects it with a `CRV1` challenge containing a
   session ID and the IdP login URL.
2. You log in in the browser. The IdP POSTs a `SAMLResponse` to `http://127.0.0.1:35001/`.
3. OpenVPN reconnects **to the same server IP** with password `CRV1::<session>::<SAMLResponse>`.

Stock OpenVPN cannot send a password that long, so the build carries the AWS patch
(`patches/openvpn-v2.6.23-aws.patch`, which only enlarges buffers and length fields).

```
 Quick Settings toggle ──┐                       system D-Bus
 AWS VPN app ────────────┼──────────────────────> awsvpnd (root, sandboxed by systemd)
   └ one-shot listener 127.0.0.1:35001             ├ phase 1: openvpn as user `awsvpn`
                                                   └ phase 2: openvpn, drops to `awsvpn` once up
```

## Build and install (Fedora 44)

```sh
sudo dnf install golang rpm-build gnupg2 openssl-devel lzo-devel lz4-devel \
                 libnl3-devel libcap-ng-devel systemd-rpm-macros desktop-file-utils
make test
make rpm
sudo dnf install ./rpmbuild/RPMS/x86_64/awsvpn-*.rpm
gnome-extensions enable awsvpn@adelsjarlen.github.io   # then log out and back in
```

The RPM build checks the OpenVPN release tarball's signature against the pinned key in
`packaging/openvpn-signing-key.asc`, applies the patch with `--fuzz=0` and runs the tests.

## Usage

1. Open **AWS VPN** and choose **Import Profile…**, then pick the `.ovpn` from your administrator
   (this asks for your admin password once).
2. Click **Connect**, or use the **AWS VPN** toggle in Quick Settings. Your browser opens; sign in.
3. The toggle shows *Connected*. Click it again to disconnect.

From a terminal: `awsvpn --connect` / `awsvpn --disconnect`. The daemon logs to `journalctl -u awsvpnd`.

## Development

```sh
make test                                       # go vet, go test -race, python tests
busctl --system introspect io.github.AdelsJarlen.AwsVpn1 /io/github/AdelsJarlen/AwsVpn1
```

To update the AWS patch for a newer AWS source drop, see `scripts/extract-aws-patch.sh`.

## License

MIT for this project. The bundled OpenVPN binary is GPL-2.0 with the OpenSSL exception.
