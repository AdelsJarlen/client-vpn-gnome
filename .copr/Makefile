# Entry point for Fedora COPR's "make srpm" build method:
#   make -f .copr/Makefile srpm outdir=<dir>
# The SRPM carries vendored Go modules and the signed OpenVPN tarball, so the
# binary RPM build itself needs no network access.

outdir ?= $(CURDIR)/.copr/out

srpm:
	command -v go >/dev/null && command -v git >/dev/null && command -v curl >/dev/null \
		|| dnf -y install git golang curl make rpm-build
	git config --global --add safe.directory "$(CURDIR)"
	rm -rf "$(CURDIR)/.copr/build"
	$(MAKE) srpm TOPDIR="$(CURDIR)/.copr/build"
	mkdir -p "$(outdir)"
	cp "$(CURDIR)"/.copr/build/SRPMS/*.src.rpm "$(outdir)/"

.PHONY: srpm
