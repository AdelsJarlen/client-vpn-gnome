%global ovpn_version 2.7.8
%global app_id io.github.AdelsJarlen.AwsVpn
%global ext_uuid awsvpn@adelsjarlen.github.io
# Go binaries are built without Fedora's go-rpm-macros; skip debuginfo.
%global debug_package %{nil}

Name:           awsvpn
Version:        0.2.0
Release:        1%{?dist}
Summary:        AWS Client VPN (SAML) for GNOME: daemon, app and Quick Settings toggle
License:        MIT AND GPL-2.0-only WITH openvpn-openssl-exception
URL:            https://github.com/AdelsJarlen/aws-vpn-client

Source0:        %{name}-%{version}.tar.gz
Source1:        https://swupdate.openvpn.org/community/releases/openvpn-%{ovpn_version}.tar.gz
Source2:        https://swupdate.openvpn.org/community/releases/openvpn-%{ovpn_version}.tar.gz.asc
# OpenVPN Security Mailing List <security@openvpn.net>
# F554 A368 7412 CFFE BDEF  E0A3 12F5 F7B4 2F2B 01E7
Source3:        openvpn-signing-key.asc

BuildRequires:  golang >= 1.22
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  gnupg2
BuildRequires:  openssl-devel
BuildRequires:  lzo-devel
BuildRequires:  lz4-devel
BuildRequires:  libnl3-devel
BuildRequires:  libcap-ng-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  desktop-file-utils

Requires:       dbus
Requires:       polkit
Requires:       systemd-resolved
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita >= 1.6
Recommends:     gnome-shell >= 50
%{?systemd_requires}

%description
A hardened client for AWS Client VPN endpoints that use SAML federated
authentication. It consists of a small privileged D-Bus service (awsvpnd)
that drives a patched OpenVPN %{ovpn_version}, a libadwaita application for
importing profiles and logging in, and a GNOME Shell Quick Settings toggle.

%prep
%{gpgverify} --keyring='%{SOURCE3}' --signature='%{SOURCE2}' --data='%{SOURCE1}'
%setup -q
%setup -q -T -D -a 1
pushd openvpn-%{ovpn_version}
patch -p1 --fuzz=0 < ../patches/openvpn-v%{ovpn_version}-aws.patch
popd

%build
pushd openvpn-%{ovpn_version}
# Built from the release tarball: keep OpenVPN's version script from
# picking up git metadata of the surrounding checkout.
export GIT_DIR=/nonexistent
%configure \
    --disable-plugins \
    --disable-debug \
    --with-crypto-library=openssl
%make_build
unset GIT_DIR
popd

pushd daemon
export GOFLAGS="-mod=vendor -trimpath -buildvcs=false" GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=1
export CGO_CFLAGS="%{optflags}" CGO_LDFLAGS="%{build_ldflags}"
go build -buildmode=pie -ldflags "-linkmode=external" -o awsvpnd ./cmd/awsvpnd
popd

%check
pushd daemon
GOFLAGS="-mod=vendor" GOPROXY=off GOTOOLCHAIN=local go test ./...
popd
./openvpn-%{ovpn_version}/src/openvpn/openvpn --version | head -1 | grep -q "OpenVPN %{ovpn_version}"
desktop-file-validate app/data/%{app_id}.desktop

%install
install -Dm0755 openvpn-%{ovpn_version}/src/openvpn/openvpn %{buildroot}%{_libexecdir}/awsvpn/openvpn
install -Dm0755 daemon/awsvpnd %{buildroot}%{_libexecdir}/awsvpn/awsvpnd

install -Dm0644 packaging/awsvpnd.service %{buildroot}%{_unitdir}/awsvpnd.service
install -Dm0644 packaging/io.github.AdelsJarlen.AwsVpn1.conf %{buildroot}%{_datadir}/dbus-1/system.d/io.github.AdelsJarlen.AwsVpn1.conf
install -Dm0644 packaging/io.github.AdelsJarlen.AwsVpn1.service %{buildroot}%{_datadir}/dbus-1/system-services/io.github.AdelsJarlen.AwsVpn1.service
install -Dm0644 packaging/io.github.AdelsJarlen.AwsVpn.policy %{buildroot}%{_datadir}/polkit-1/actions/io.github.AdelsJarlen.AwsVpn.policy
install -Dm0644 packaging/awsvpn.sysusers %{buildroot}%{_sysusersdir}/awsvpn.conf

install -Dm0755 app/bin/awsvpn %{buildroot}%{_bindir}/awsvpn
install -dm0755 %{buildroot}%{_datadir}/awsvpn/awsvpn
install -m0644 app/awsvpn/*.py %{buildroot}%{_datadir}/awsvpn/awsvpn/
# Read by the update checker to compare against upstream releases.
printf '%%s\n' '%{ovpn_version}' > %{buildroot}%{_datadir}/awsvpn/openvpn-version
install -Dm0644 packaging/%{app_id}.service %{buildroot}%{_datadir}/dbus-1/services/%{app_id}.service
install -Dm0644 packaging/awsvpn-update-check.service %{buildroot}%{_userunitdir}/awsvpn-update-check.service
install -Dm0644 packaging/awsvpn-update-check.timer %{buildroot}%{_userunitdir}/awsvpn-update-check.timer
install -Dm0644 packaging/80-awsvpn.preset %{buildroot}%{_userpresetdir}/80-awsvpn.preset
install -Dm0644 app/data/%{app_id}.desktop %{buildroot}%{_datadir}/applications/%{app_id}.desktop
install -Dm0644 app/data/%{app_id}.metainfo.xml %{buildroot}%{_metainfodir}/%{app_id}.metainfo.xml
install -Dm0644 app/data/icons/%{app_id}.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg

install -dm0755 %{buildroot}%{_datadir}/gnome-shell/extensions/%{ext_uuid}
install -m0644 extension/%{ext_uuid}/* %{buildroot}%{_datadir}/gnome-shell/extensions/%{ext_uuid}/

%post
%systemd_post awsvpnd.service
%systemd_user_post awsvpn-update-check.timer

%preun
%systemd_preun awsvpnd.service
%systemd_user_preun awsvpn-update-check.timer

%postun
%systemd_postun_with_restart awsvpnd.service

%files
%license LICENSE
%doc README.md SECURITY.md
%dir %{_libexecdir}/awsvpn
%{_libexecdir}/awsvpn/awsvpnd
%{_libexecdir}/awsvpn/openvpn
%{_unitdir}/awsvpnd.service
%{_datadir}/dbus-1/system.d/io.github.AdelsJarlen.AwsVpn1.conf
%{_datadir}/dbus-1/system-services/io.github.AdelsJarlen.AwsVpn1.service
%{_datadir}/polkit-1/actions/io.github.AdelsJarlen.AwsVpn.policy
%{_sysusersdir}/awsvpn.conf
%{_bindir}/awsvpn
%{_datadir}/awsvpn/
%{_datadir}/applications/%{app_id}.desktop
%{_datadir}/dbus-1/services/%{app_id}.service
%{_userunitdir}/awsvpn-update-check.service
%{_userunitdir}/awsvpn-update-check.timer
%{_userpresetdir}/80-awsvpn.preset
%{_metainfodir}/%{app_id}.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg
%{_datadir}/gnome-shell/extensions/%{ext_uuid}/

%changelog
* Mon Oct 19 2026 Ola Aasen Juul <94843506+AdelsJarlen@users.noreply.github.com> - 0.2.0-1
- Port to OpenVPN 2.7.8. write_string()'s new 16-bit cap is lifted along
  with the 32-bit length fields. Data channel offload is off by default
  (awsvpnd -dco enables it); --persist-key is no longer passed.

* Mon Oct 19 2026 Ola Aasen Juul <94843506+AdelsJarlen@users.noreply.github.com> - 0.1.2-1
- App: show/hide Details instantly instead of with AdwExpanderRow's slide
  animation, which made the window fit itself to a mid-animation size.

* Sun Oct 18 2026 Ola Aasen Juul <94843506+AdelsJarlen@users.noreply.github.com> - 0.1.1-1
- App: keep the status area and connect button outside the scroll area,
  make Details collapsible and fit the window height to its content.
- Parenthesize enlarged size macros in the AWS OpenVPN patch.
- Daily user timer checks for newer OpenVPN releases and notifies; the app
  shows a banner. Add `make openvpn-bump V=x.y.z` to rebase the patch.
- App is D-Bus activatable so notification buttons work when it is closed.

* Sun Oct 18 2026 Ola Aasen Juul <94843506+AdelsJarlen@users.noreply.github.com> - 0.1.0-1
- Initial package: Go daemon, libadwaita app, GNOME Shell extension,
  OpenVPN 2.6.23 with the AWS SAML patch.
