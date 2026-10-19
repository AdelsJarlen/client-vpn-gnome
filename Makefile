VERSION      := 0.3.1
OVPN_VERSION := 2.7.8
OVPN_URL     := https://swupdate.openvpn.org/community/releases/openvpn-$(OVPN_VERSION).tar.gz
TOPDIR       := $(CURDIR)/rpmbuild
SOURCES      := $(TOPDIR)/SOURCES

.PHONY: all test lint vendor sources rpm srpm clean openvpn-bump

all: test

test:
	@cd daemon && unformatted="$$(gofmt -l cmd internal)" && { [ -z "$$unformatted" ] || { echo "gofmt needed:"; echo "$$unformatted"; exit 1; }; }
	cd daemon && go vet ./... && go test -race ./...
	python3 -m py_compile app/clientvpn/*.py
	cd app && python3 -W ignore -m unittest discover -s tests
	@command -v ruff >/dev/null && ruff check app || true

vendor:
	cd daemon && go mod tidy && go mod vendor

$(SOURCES)/openvpn-$(OVPN_VERSION).tar.gz:
	mkdir -p $(SOURCES)
	curl -fsSLo $@ $(OVPN_URL)

$(SOURCES)/openvpn-$(OVPN_VERSION).tar.gz.asc:
	mkdir -p $(SOURCES)
	curl -fsSLo $@ $(OVPN_URL).asc

sources: vendor $(SOURCES)/openvpn-$(OVPN_VERSION).tar.gz $(SOURCES)/openvpn-$(OVPN_VERSION).tar.gz.asc
	cp packaging/openvpn-signing-key.asc $(SOURCES)/
	{ git ls-files --cached --others --exclude-standard; find daemon/vendor -type f; } | sort -u | \
	  tar czf $(SOURCES)/client-vpn-gnome-$(VERSION).tar.gz --transform 's,^,client-vpn-gnome-$(VERSION)/,' -T -

rpm: sources
	rpmbuild -ba --define "_topdir $(TOPDIR)" packaging/client-vpn-gnome.spec
	@ls -1 $(TOPDIR)/RPMS/*/client-vpn-gnome-*.rpm

srpm: sources
	rpmbuild -bs --define "_topdir $(TOPDIR)" packaging/client-vpn-gnome.spec

# Rebase the AWS patch onto a newer OpenVPN maintenance release: make openvpn-bump V=2.6.24
openvpn-bump:
	@test -n "$(V)" || { echo "usage: make openvpn-bump V=x.y.z"; exit 2; }
	scripts/bump-openvpn.sh $(V)

clean:
	rm -rf $(TOPDIR) daemon/vendor daemon/client-vpnd
