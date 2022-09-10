package grpc_proxy

import (
	"flag"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Configurator func(*server)

// Deprecated: use WithServerOptions instead
func WithOptions(options ...grpc.ServerOption) Configurator {
	return func(s *server) {
		s.serverOptions = append(s.serverOptions, options...)
	}
}

// WithServerOptions allows you to supply a list of grpc.ServerOption
// that will be passed to grpc.NewServer when creating the proxy.
func WithServerOptions(options ...grpc.ServerOption) Configurator {
	return func(s *server) {
		s.serverOptions = append(s.serverOptions, options...)
	}
}

// WithDialOptions allows you to supply a list of grpc.DialOption
// that will be passed to grpc.Dial when dialing downstream servers.
func WithDialOptions(options ...grpc.DialOption) Configurator {
	return func(s *server) {
		s.dialOptions = append(s.dialOptions, options...)
	}
}

func WithInterceptor(interceptor grpc.StreamServerInterceptor) Configurator {
	return func(s *server) {
		s.serverOptions = append(s.serverOptions, grpc.StreamInterceptor(recoverWrapper(s, interceptor)))
	}
}

func recoverWrapper(s *server, interceptor grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = status.Errorf(codes.Internal, "proxy error: %v", r)
				s.logger.WithError(err).Warn("panic in StreamHandler: ", string(debug.Stack()))
			}
		}()
		return interceptor(srv, ss, info, handler)
	}
}

func UsingTLS(certFile, keyFile string) Configurator {
	return func(s *server) {
		s.certFile = certFile
		s.keyFile = keyFile
	}
}

func Port(port int) Configurator {
	return func(s *server) {
		s.port = port
	}
}

func WithDialer(dialer ContextDialer) Configurator {
	return func(s *server) {
		s.dialer = dialer
	}
}

var (
	fNetworkInterface  string
	fPort              int
	fTargetDomains     string
	fCaCert            string
	fKeyFile           string
	fDestination       string
	fLogLevel          string
	fEnableSystemProxy bool
	fTLSSecretsFile    string
)

// Must be called before flag.Parse() if using the DefaultFlags option
func RegisterDefaultFlags() {
	flag.StringVar(&fNetworkInterface, "interface", "localhost", "Network interface to listen on. By default listens on the localhost interface.")
	flag.IntVar(&fPort, "port", 0, "Port to listen on.")
	flag.StringVar(&fTargetDomains, "domains", "google.com", "The domains to mitm")
	flag.StringVar(&fCaCert, "ca_cert", "", "Certificate Authority public key to use for serving using TLS.")
	flag.StringVar(&fKeyFile, "ca_key", "", "Private key of the Certificate Authority to use.")
	flag.StringVar(&fDestination, "destination", "", "Destination server to forward requests to if no destination can be inferred from the request itself. This is generally only used for clients not supporting HTTP proxies.")
	flag.StringVar(&fLogLevel, "log_level", logrus.InfoLevel.String(), "Set the log level that grpc-proxy will log at. Values are {error, warning, info, debug}")
	flag.BoolVar(&fEnableSystemProxy, "system_proxy", false, "Automatically configure system to use this as the proxy for all connections.")
	flag.StringVar(&fTLSSecretsFile, "tls_secrets_file", "", "Secrets file to write the TLS master secrets in order to decrypt TLS traffic with different tools such as Wireshark.")
}

// This must be used after a call to flag.Parse()
func DefaultFlags() Configurator {
	return func(s *server) {
		s.networkInterface = fNetworkInterface
		s.port = fPort
		s.targetDomains = fTargetDomains
		s.certFile = fCaCert
		s.keyFile = fKeyFile
		s.destination = fDestination
		s.enableSystemProxy = fEnableSystemProxy
		s.tlsSecretsFile = fTLSSecretsFile
	}
}
