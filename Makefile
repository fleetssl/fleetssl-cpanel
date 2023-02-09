.PHONY: all clean package deploy release translate clean-rpm docker-build docker-build-setup test

VER=`cat VERSION`
ITERATION=`cat ITERATION`
CWD=`pwd`
ARCH?=amd64
GOARCH?=amd64

all: letsencrypt.live.cgi

letsencrypt.live.cgi:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GO111MODULE=on go build -ldflags "-s -w -X bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common.AppVersion=$(VER)" -o letsencrypt.live.cgi cmd/letsencrypt.go

translate:
	cat cmd/cgi/*.go | gawk 'match($$0, /T[SEF]\(\"(.+?)\"\)/, m) { print "`" m[1] "`=" }' > plugin/vendor.en.ini_unsorted
	cat plugin/templates/*.html | gawk 'match($$0, /T[SEF] `(.+?)`/, m) { print "`" m[1] "`=" }' >> plugin/vendor.en.ini_unsorted
	sort -u plugin/vendor.en.ini_unsorted > plugin/vendor.en.ini
	rm -f plugin/vendor.en.ini_unsorted

package: letsencrypt.live.cgi translate
	cp letsencrypt.live.cgi plugin/
	@rm -f letsencrypt-$(VER).tar.gz
	tar czf letsencrypt-$(VER).tar.gz --transform s/plugin/letsencrypt-plugin-$(VER)/ plugin/

rpm: letsencrypt.live.cgi translate
	@rm -rf fpm; mkdir fpm
	cp -r plugin/* fpm/ 
	cp letsencrypt.live.cgi fpm/
	mv fpm/templates/* fpm/ && rmdir fpm/templates
	find fpm/ -type d -exec chmod 755 {} \;
	find fpm/ -type f -exec chmod 644 {} \;
	chmod a+x fpm/letsencrypt.live.cgi
	find fpm/ -type f -name "*.sh" -exec dos2unix {} \;

	fpm -a $(ARCH) -s dir -t rpm -n letsencrypt-cpanel -v $(VER) --iteration $(ITERATION) -C ./fpm/ \
	--before-install fpm/pre-install.sh --after-install fpm/post-install.sh \
	--before-remove fpm/uninstall.sh \
	--prefix /opt/fleetssl-cpanel \
	--rpm-os linux --url https://cpanel.fleetssl.com/ \
	--depends bc

	fpm -a $(ARCH) -s dir -t deb -n letsencrypt-cpanel -v $(VER) --iteration $(ITERATION) -C ./fpm/ \
	--before-install fpm/pre-install.sh --after-install fpm/post-install.sh \
	--before-remove fpm/uninstall.sh \
	--prefix /opt/fleetssl-cpanel \
	--url https://cpanel.fleetssl.com/ \
	--depends bc --depends init-system-helpers

	@rm -rf fpm

deploy:
	rsync --progress -vz letsencrypt-cpanel-$(VER)-$(ITERATION).x86_64.rpm root@plugindev.fleetssl.com:/root/
	ssh root@plugindev.fleetssl.com "rpm -ivh --force letsencrypt-cpanel-$(VER)-$(ITERATION).x86_64.rpm"

release-rpm:
	ssh web@cpanel.fleetssl.com "rm -f /tmp/letsencrypt-cpanel_**.deb"
	rsync --progress -vz letsencrypt-cpanel-**.rpm web@cpanel.fleetssl.com:/home/web/repo/
	rsync --progress -vz  letsencrypt-cpanel_**.deb web@cpanel.fleetssl.com:/tmp/
	ssh web@cpanel.fleetssl.com "createrepo --update /home/web/repo"
	ssh web@cpanel.fleetssl.com "reprepro -b /home/web/repo/ubuntu --ask-passphrase includedeb focal /tmp/letsencrypt-cpanel_*.deb"
	ssh root@fleetssl.com "sh -c '/root/invalidate-cdn.sh'"

package-source: translate
	@rm -rf letsencrypt-cpanel-src; mkdir letsencrypt-cpanel-src
	\cp -r Dockerfile cmd plugin internal VERSION ITERATION letsencrypt-cpanel.repo go.mod go.sum letsencrypt-cpanel-src/
	\cp Makefile.public letsencrypt-cpanel-src/Makefile
	tar zcf letsencrypt-cpanel-$(VER).src.tar.gz letsencrypt-cpanel-src/
	@rm -rf letsencrypt-cpanel-src

publish-source: package-source
	scp letsencrypt-cpanel-$(VER).src.tar.gz web@cpanel.fleetssl.com:/home/web/source/

docker-build-setup:
	sudo docker build -t le-build .

docker-build: clean clean-rpm
	sudo docker run --rm -t -e "ARCH=i386" -e "GOARCH=386" -v $(CWD)/.gomodcache:/go/pkg/mod -v $(CWD):/go/src/bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel le-build
	sudo docker run --rm -t -e "ARCH=amd64" -e "GOARCH=amd64" -v $(CWD)/.gomodcache:/go/pkg/mod -v $(CWD):/go/src/bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel le-build

clean-rpm:
	rm -f *.rpm
	rm -f rpm/*.rpm
	rm -f *.deb
	rm -f *.src.tar.gz

clean:
	rm -f letsencrypt.live.cgi plugin/letsencrypt.live.cgi 

generate:
	go generate ./cmd/...

test:
	go test -v ./cmd/daemon/
