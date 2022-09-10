package tlsmux

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bradleyjkemp/grpc-tools/internal/peekconn"
	"github.com/sirupsen/logrus"
)

// This file implements a listener that splits received connections
// into two listeners depending on whether the connection is (likely)
// a TLS connection. It does this by peeking at the first few bytes
// of the connection and seeing if it looks like a TLS handshake.

const (
	http2NextProtoTLS = "h2"
)

type tlsMuxListener struct {
	net.Listener
	close *sync.Once
	conns <-chan net.Conn
	errs  <-chan error
}

func (c *tlsMuxListener) Accept() (net.Conn, error) {
	select {
	case conn := <-c.conns:
		return conn, nil
	case err := <-c.errs:
		return nil, err
	}
}

func (c *tlsMuxListener) Close() error {
	var err error
	c.close.Do(func() {
		err = c.Listener.Close()
	})
	return err
}

func New(logger logrus.FieldLogger, listener net.Listener, caCert *x509.Certificate, caKey crypto.PrivateKey, targetDomains string, keyLogWriter io.Writer) (net.Listener, net.Listener) {
	var nonTLSConns = make(chan net.Conn, 128) // TODO decide on good buffer sizes for these channels
	var nonTLSErrs = make(chan error, 128)
	var tlsConns = make(chan net.Conn, 128)
	var tlsErrs = make(chan error, 128)
	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				nonTLSErrs <- err
				tlsErrs <- err
				continue
			}

			go func() {
				conn := peekconn.New(rawConn)

				isTLS, err := conn.PeekMatch(tlsPattern, tlsPeekSize)
				if err != nil {
					nonTLSErrs <- err
					tlsErrs <- err
				}
				if isTLS {
					var targetDomainsRegex *regexp.Regexp

					if targetDomains == "" {
						targetDomainsRegex = nil
					} else {
						targetDomainsRegex = regexp.MustCompile(targetDomains)
					}

					handleTLSConn(logger, conn, targetDomainsRegex, tlsConns)
				} else {
					nonTLSConns <- conn
				}
			}()

		}
	}()
	closer := &sync.Once{}
	nonTLSListener := nonHTTPBouncer{
		logger,
		&tlsMuxListener{
			Listener: listener,
			close:    closer,
			conns:    nonTLSConns,
		},
		false,
	}

	tlsConfig := &tls.Config{
		KeyLogWriter: keyLogWriter,
	}
	tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return createCertificate(caCert, caKey, chi.ServerName), nil
	}

	// Support HTTP/2: https://golang.org/pkg/net/http/?m=all#Serve
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, http2NextProtoTLS)
	tlsListener := nonHTTPBouncer{
		logger,
		tls.NewListener(&tlsMuxListener{
			Listener: listener,
			close:    closer,
			conns:    tlsConns,
		}, tlsConfig),
		true,
	}
	return nonTLSListener, tlsListener
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func generateKey() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func createCertificate(caCert *x509.Certificate, caKey crypto.PrivateKey, domain string) *tls.Certificate {
	if caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key is missing")
	}

	priv, err := generateKey()
	fatalIfErr(err, "ERROR: can't generate private key for new certificate")

	pub := priv.(crypto.Signer).Public()
	expiration := time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"System Unit Ltd"},
			OrganizationalUnit: []string{"System Unit"},
		},

		NotBefore: time.Now(), NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	tpl.DNSNames = append(tpl.DNSNames, domain)
	tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	rawCert, err := x509.CreateCertificate(rand.Reader, tpl, caCert, pub, caKey)
	fatalIfErr(err, "failed to generate certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCert})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)

	fatalIfErr(err, "failed to encode certificate key")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	fatalIfErr(err, "ERROR: cannot generate key pair!")

	return &cert
}

func handleTLSConn(logger logrus.FieldLogger, conn net.Conn, targetDomains *regexp.Regexp, tlsConns chan net.Conn) {
	logger.Debugf("Handling TLS connection %v", conn)

	proxConn, ok := conn.(proxiedConnection)
	if !ok {
		tlsConns <- conn
		return
	}

	if proxConn.OriginalDestination() == "" {
		logger.Debug("Connection has no original destination so must intercept")
		// cannot be forwarded so must accept regardless of whether we are able to intercept
		tlsConns <- conn
		return
	}

	logger.Debugf("Got TLS connection for destination %s", proxConn.OriginalDestination())

	// trim the port suffix
	originalHostname := strings.Split(proxConn.OriginalDestination(), ":")[0]
	// Accept target domain regex or any ip that perform TLS
	if targetDomains != nil && (targetDomains.MatchString(originalHostname) || net.ParseIP(originalHostname) != nil) {
		// the certificate we have allows us to intercept this connection
		tlsConns <- conn
		return
	}

	// cannot intercept so will just transparently proxy instead
	logger.Debugf("No certificate able to intercept connections to %s, proxying instead.", originalHostname)
	destConn, err := net.Dial(conn.LocalAddr().Network(), proxConn.OriginalDestination())
	if err != nil {
		logger.WithError(err).Debugf("Failed proxying connection to %s, Error while dialing.", originalHostname)
		_ = conn.Close()
		return
	}
	err = forwardConnection(
		conn,
		destConn,
	)
	if err != nil {
		logger.WithError(err).Warnf("Error proxying connection to %s.", originalHostname)
	}
}

var (
	tlsPattern  = regexp.MustCompile(`^\x16\x03[\x00-\x03]`) // TLS handshake byte + version number
	tlsPeekSize = 3
)

// nonHTTPBouncer wraps a net.Listener and detects whether or not
// the connection is HTTP. If not then it proxies the connection
// to the original destination.
// This is a single purpose version of github.com/soheilhy/cmux
type nonHTTPBouncer struct {
	logger logrus.FieldLogger
	net.Listener
	tls bool
}

var (
	httpPeekSize = 8
	// These are the HTTP methods we are interested in handling. Anything else gets bounced.
	httpPattern = regexp.MustCompile(`^(CONNECT)|(POST)|(PRI) `)
)

type proxiedConnection interface {
	OriginalDestination() string
}

func (b nonHTTPBouncer) Accept() (net.Conn, error) {
	conn, err := b.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxConn, ok := conn.(proxiedConnection)
	if !ok || proxConn.OriginalDestination() == "" {
		// unknown (direct?) connection, must handle it ourselves
		return conn, nil
	}

	peekedConn := peekconn.New(conn)
	match, err := peekedConn.PeekMatch(httpPattern, httpPeekSize)
	if err != nil {
		return nil, err
	}
	if match {
		// this is a connection we want to handle
		return peekedConn, nil
	}
	b.logger.Debugf("Bouncing non-HTTP connection to destination %s", proxConn.OriginalDestination())

	// proxy this connection without interception
	go func() {
		destination := proxConn.OriginalDestination()
		var destConn net.Conn
		if b.tls {
			destConn, err = tls.Dial(conn.LocalAddr().Network(), destination, nil)
		} else {
			destConn, err = net.Dial(conn.LocalAddr().Network(), destination)
		}
		if err != nil {
			b.logger.WithError(err).Warnf("Error proxying connection to %s.", destination)
			return
		}

		err := forwardConnection(
			peekedConn,
			destConn,
		)
		if err != nil {
			b.logger.WithError(err).Warnf("Error proxying connection to %s.", destination)
		}
	}()

	return b.Accept()
}
