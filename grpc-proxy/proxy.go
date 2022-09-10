package grpc_proxy

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/bradleyjkemp/grpc-tools/internal"
	"github.com/bradleyjkemp/grpc-tools/internal/codec"
	"github.com/bradleyjkemp/grpc-tools/internal/proxy_settings"
	"github.com/bradleyjkemp/grpc-tools/internal/proxydialer"
	"github.com/bradleyjkemp/grpc-tools/internal/tlsmux"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpproxy"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

type ContextDialer = func(context.Context, string) (net.Conn, error)

type server struct {
	serverOptions []grpc.ServerOption
	grpcServer    *grpc.Server
	logger        logrus.FieldLogger

	networkInterface string
	port             int
	targetDomains    string
	certFile         string
	keyFile          string
	caCert           *x509.Certificate
	caKey            crypto.PrivateKey

	destination string
	connPool    *internal.ConnPool
	dialOptions []grpc.DialOption
	dialer      ContextDialer

	enableSystemProxy bool

	tlsSecretsFile string

	listener net.Listener
}

func New(configurators ...Configurator) (*server, error) {
	logger := logrus.New()
	s := &server{
		logger:           logger,
		dialer:           proxydialer.NewProxyDialer(httpproxy.FromEnvironment().ProxyFunc()),
		networkInterface: "localhost", // default to just localhost if no other interface is chosen
	}
	s.serverOptions = []grpc.ServerOption{
		grpc.MaxRecvMsgSize(64 * 1024 * 1024),      // Up the max message size from 4MB to 64MB (to give headroom for intercepting services who've upped theirs)
		grpc.CustomCodec(codec.NoopCodec{}),        // Allows for passing raw []byte messages around
		grpc.UnknownServiceHandler(s.proxyHandler), // All services are unknown so will be proxied
	}

	for _, configurator := range configurators {
		configurator(s)
	}

	// Have to initialise the connpool now because
	// the dialer may been changed by options
	s.connPool = internal.NewConnPool(logger, s.dialer)

	if fLogLevel != "" {
		level, err := logrus.ParseLevel(fLogLevel)
		if err != nil {
			return nil, err
		}
		logger.SetLevel(level)
	}

	if s.certFile != "" && s.keyFile != "" {
		var err error

		certPEMBlock, err := ioutil.ReadFile(s.certFile)
		if err != nil {
			return nil, err
		}

		certDERBlock, _ := pem.Decode(certPEMBlock)
		if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
			log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
		}

		s.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			return nil, err
		}

		keyPEMBlock, err := ioutil.ReadFile(s.keyFile)
		if err != nil {
			return nil, err
		}

		keyDERBlock, _ := pem.Decode(keyPEMBlock)
		if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
			log.Fatalln("ERROR: failed to read the CA key: unexpected content")
		}

		s.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.networkInterface, s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on interface (%s:%d): %v", s.networkInterface, s.port, err)
	}
	s.logger.Infof("Listening on %s", s.listener.Addr())
	if s.caCert != nil {
		s.logger.Infof("Intercepting TLS connections to domains: %s", s.targetDomains)
	} else {
		s.logger.Infof("Not intercepting TLS connections")
	}

	grpcWebHandler := grpcweb.WrapServer(
		grpc.NewServer(s.serverOptions...),
		grpcweb.WithCorsForRegisteredEndpointsOnly(false), // because we are proxying
		grpcweb.WithOriginFunc(func(_ string) bool { return true }),
	)

	proxyLis := newProxyListener(s.logger, s.listener)
	httpReverseProxy := newReverseProxy(s.logger)
	httpServer := newHttpServer(s.logger, grpcWebHandler, proxyLis.internalRedirect, proxyLis.getProxiedOriginalDestination, httpReverseProxy)
	httpsServer := withHttpsMiddleware(newHttpServer(s.logger, grpcWebHandler, proxyLis.internalRedirect, proxyLis.getProxiedOriginalDestination, httpReverseProxy))

	// Use file path for Master Secrets file is specified. Send to /dev/null if not.
	keyLogWriter := ioutil.Discard
	if s.tlsSecretsFile != "" {
		keyLogWriter, err = os.OpenFile(s.tlsSecretsFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed opening secrets file on path: %s", s.tlsSecretsFile)
		}
	}
	httpLis, httpsLis := tlsmux.New(s.logger, proxyLis, s.caCert, s.caKey, s.targetDomains, keyLogWriter)

	errChan := make(chan error)
	if s.enableSystemProxy {
		disableProxy, err := proxy_settings.EnableProxy(s.listener.Addr().String())
		if err != nil {
			return errors.Wrap(err, "failed to enable system proxy")
		}
		s.logger.Info("Enabled system proxy.")
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			errChan <- disableProxy()
		}()
	}

	go func() {
		errChan <- httpServer.Serve(httpLis)
	}()
	go func() {
		// the TLSMux unwraps TLS for us so we use Serve instead of ServeTLS
		errChan <- httpsServer.Serve(httpsLis)
	}()

	return <-errChan
}
