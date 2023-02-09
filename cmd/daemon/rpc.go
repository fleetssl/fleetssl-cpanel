package daemon

import (
	"encoding/base64"
	"errors"
	"net"
	"runtime/debug"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var ah64 string

var rpcRestartCh chan struct{} = make(chan struct{}, 0)
var rpcRestartFunc func() error

func ListenRpc(listen string, a Api, lis net.Listener) error {
	var err error
	log.Info("Starting up the RPC server")

	if lis == nil {
		lis, err = net.Listen("tcp", listen)
		if err != nil {
			return err
		}
	}

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(rpcAuth),
	}

	// transport security for grpc
	useTls, x509Cert, cert := common.GetTLSForRPC()
	if useTls {
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	}

	rpcServer := grpc.NewServer(opts...)
	pb.RegisterPluginServer(rpcServer, a)

	go rpcServer.Serve(lis)

	rpcRestartFunc = func(srv *grpc.Server, lis net.Listener, a Api) func() error {
		return func() error {
			if rpcServer != nil {
				log.Info("Stopping RPC server")
				rpcServer.Stop()
			}

			log.Info("Restarting RPC server in 1 second")
			time.Sleep(time.Second)
			return ListenRpc(listen, a, nil)
		}
	}(rpcServer, lis, a)

	if useTls {
		if x509Cert.NotAfter.Before(time.Now()) {
			log.WithField("Expires", x509Cert.NotAfter).Info("rpc cert is expired")
			return nil
		}

		go func(t time.Time) {
			select {
			case <-time.After(t.Sub(time.Now())):
				break
			case <-rpcRestartCh:
				log.Info("Restart triggered in rpc (tls)")
				break
			}
			if err := rpcRestartFunc(); err != nil {
				log.WithError(err).Error("Failed to restart RPC server")
			}
		}(x509Cert.NotAfter)
	} else {
		go func() {
			<-rpcRestartCh
			log.Info("Restart triggered in rpc (insecure)")
			if err := rpcRestartFunc(); err != nil {
				log.WithError(err).Error("Failed to restart RPC server")
			}
		}()
	}

	return nil
}

func rpcAuth(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Metadata missing")
	}

	h, ok := md["accesshash"]
	if !ok || len(h) == 0 {
		return nil, errors.New("Accesshash missing")
	}

	ahToCompare := h[0]

	if ah64 == "" {
		sBuf, err := common.ReadApiToken()
		if err != nil {
			log.WithError(err).Error("Failed to read accesshash for rpc auth")
			return nil, errors.New("Internal error")
		}
		sBuf = strings.Replace(sBuf, "\n", "", -1)
		sBuf = strings.TrimSpace(strings.Replace(sBuf, "\r", "", -1))
		ah64 = base64.StdEncoding.EncodeToString([]byte(sBuf))
	}

	if ah64 != ahToCompare {
		return nil, errors.New("Unauthorized")
	}

	// recover from panics in the end-handlers
	defer func() {
		if err := recover(); err != nil {
			log.WithField("Panic", err).Warn("Recovered from fata panic in GRPC handler")
			debug.PrintStack()
		}
	}()

	return handler(ctx, req)
}
