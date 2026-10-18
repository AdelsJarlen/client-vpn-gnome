VERSION      := 0.1.0
OVPN_VERSION := 2.6.23
OVPN_URL     := https://swupdate.openvpn.org/community/releases/openvpn-$(OVPN_VERSION).tar.gz
TOPDIR       := $(CURDIR)/rpmbuild
SOURCES      := $(TOPDIR)/SOURCES

.PHONY: all test lint vendor sources rpm srpm clean

all: test

test:
	cd daemon && go vet ./... && go test -race ./...
	python3 -m py_compile app/awsvpn/*.py
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
	  tar czf $(SOURCES)/awsvpn-$(VERSION).tar.gz --transform 's,^,awsvpn-$(VERSION)/,' -T -

rpm: sources
	rpmbuild -ba --define "_topdir $(TOPDIR)" packaging/awsvpn.spec
	@ls -1 $(TOPDIR)/RPMS/*/awsvpn-*.rpm

srpm: sources
	rpmbuild -bs --define "_topdir $(TOPDIR)" packaging/awsvpn.spec

clean:
	rm -rf $(TOPDIR) daemon/vendor daemon/awsvpnd
