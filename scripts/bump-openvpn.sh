#!/usr/bin/env bash
# Move the bundled OpenVPN to a new upstream release in the same series:
# rebase the AWS patch onto the new tag (no fuzz allowed), and update the
# version in the Makefile and RPM spec. Builds nothing; run `make rpm` after.
#
# Usage: scripts/bump-openvpn.sh 2.6.24
set -euo pipefail

new="${1:-}"
if [[ ! $new =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 NEW_VERSION   (e.g. 2.6.24)" >&2
    exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
makefile="$root/Makefile"
spec="$root/packaging/awsvpn.spec"
cur="$(sed -n 's/^OVPN_VERSION *:= *//p' "$makefile")"
old_patch="$root/patches/openvpn-v$cur-aws.patch"
new_patch="$root/patches/openvpn-v$new-aws.patch"

if [[ $new == "$cur" ]]; then
    echo "Already at OpenVPN $cur."
    exit 0
fi
if [[ ${new%.*} != "${cur%.*}" ]]; then
    echo "OpenVPN $new is a different series than $cur (${cur%.*}). The AWS patch has to be" >&2
    echo "ported by hand for a new series; this script only handles maintenance releases." >&2
    exit 1
fi
if [[ "$(printf '%s\n%s\n' "$cur" "$new" | sort -V | tail -1)" != "$new" ]]; then
    echo "OpenVPN $new is older than the current $cur." >&2
    exit 1
fi
[[ -f $old_patch ]] || { echo "missing $old_patch" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Fetching OpenVPN v$new..."
if ! git -c advice.detachedHead=false clone --quiet --depth 1 --branch "v$new" \
        https://github.com/OpenVPN/openvpn "$work/openvpn" 2>"$work/clone.log"; then
    cat "$work/clone.log" >&2
    exit 1
fi

echo "Applying the AWS patch from $cur..."
if ! (cd "$work/openvpn" && patch -p1 --fuzz=0 --no-backup-if-mismatch --quiet < "$old_patch"); then
    echo >&2
    echo "The AWS patch does not apply cleanly to OpenVPN $new." >&2
    echo "Port it by hand: clone v$new, apply $old_patch, fix the .rej hunks," >&2
    echo "then save 'git diff' (with the header of the old patch) as $new_patch." >&2
    exit 1
fi

# Keep the explanatory header of the old patch, with the version updated.
{
    sed -n '/^diff --git/q; p' "$old_patch" | sed "s/OpenVPN $cur/OpenVPN $new/g; s/v$cur/v$new/g"
    git -C "$work/openvpn" diff
} > "$new_patch"

sed -i "s/^OVPN_VERSION *:= *$cur\$/OVPN_VERSION := $new/" "$makefile"
sed -i "s/^%global ovpn_version $cur\$/%global ovpn_version $new/" "$spec"

# Bump the RPM release so `dnf upgrade` picks up the rebuilt package.
release="$(sed -n 's/^Release: *\([0-9]\+\)%{?dist}$/\1/p' "$spec")"
version="$(sed -n 's/^Version: *//p' "$spec")"
next=$((release + 1))
sed -i "s/^Release: *$release%{?dist}\$/Release:        $next%{?dist}/" "$spec"
who="$(git -C "$root" config user.name || echo awsvpn) <$(git -C "$root" config user.email || echo nobody@localhost)>"
entry="* $(LC_ALL=C date '+%a %b %d %Y') $who - $version-$next\n- Update bundled OpenVPN to $new.\n"
sed -i "s/^%changelog\$/%changelog\n$entry/" "$spec"

if git -C "$root" ls-files --error-unmatch "$old_patch" >/dev/null 2>&1; then
    git -C "$root" rm --quiet "$old_patch"
else
    rm -f "$old_patch"
fi
git -C "$root" add "$new_patch" "$makefile" "$spec"

cat <<EOF

OpenVPN bumped $cur -> $new (package $version-$next). Changes are staged.
Next:
  make rpm
  sudo dnf upgrade ./rpmbuild/RPMS/x86_64/awsvpn-$version-$next.*.rpm
  git commit -m "Update bundled OpenVPN to $new" && git push
EOF
