module bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel

go 1.19

require (
	github.com/boltdb/bolt v1.3.1
	github.com/domainr/dnsr v0.0.0-20230201081933-be41f88314d3
	github.com/eggsampler/acme/v3 v3.3.0
	github.com/fatih/color v1.14.1
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-ini/ini v1.67.0
	github.com/juju/ratelimit v1.0.2
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kardianos/service v1.2.2
	github.com/letsencrypt-cpanel/cpanelgo v1.2.1
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/crypto v0.6.0
	golang.org/x/net v0.6.0
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/urfave/cli.v1 v1.20.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/miekg/dns v1.1.50 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	google.golang.org/genproto v0.0.0-20230202175211-008b39050e57 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

// Dependencies we have hard-forked
replace github.com/kardianos/service => ./internal/github.com/kardianos/service
