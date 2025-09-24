package push_checker

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type Config struct {
	Checks []CheckConfig `yaml:"checks"`
}

type CheckConfig struct {
	Type    string `yaml:"type"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	PushUrl string `yaml:"push_url"`
}

type Checker struct {
	conf *Config
}

type Check interface {
	Run() error
}

func New(conf *Config) (*Checker, error) {
	for _, check := range conf.Checks {
		switch check.Type {
		case "smtp_tls", "smtp_ssl":
			// valid types
		default:
			return nil, fmt.Errorf("invalid check type: %s", check.Type)
		}

		if check.PushUrl == "" {
			return nil, fmt.Errorf("push_url is required for each check")
		}

		if check.Host == "" || check.Port == 0 {
			return nil, fmt.Errorf("host and port are required for checks")
		}
	}

	return &Checker{
		conf: conf,
	}, nil
}

func (c *Checker) Run() error {
	for _, check := range c.conf.Checks {
		switch check.Type {
		case "smtp_tls", "smtp_ssl":
			check, err := newSMTPCheck(check)
			if err != nil {
				return err
			}
			if err := check.Run(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported check type: %s", check.Type)
		}
	}

	return nil
}

func newSMTPCheck(check CheckConfig) (Check, error) {
	switch check.Type {
	case "smtp_tls":
		c := &SMTP_TLS{
			config: check,
		}
		return c, nil
	case "smtp_ssl":
		c := &SMTP_SSL{
			config: check,
		}
		return c, nil
	default:
		return nil, fmt.Errorf("unsupported SMTP check type: %s", check.Type)
	}
}

type SMTP_TLS struct {
	config CheckConfig
}

func readSMTPReply(r *bufio.Reader) (string, error) {
	var reply strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		reply.WriteString(line)
		// Example: "250-STARTTLS" continues, "250 OK" ends
		if len(line) >= 4 && line[3] != '-' {
			break
		}
	}
	return reply.String(), nil
}

func (s *SMTP_TLS) Run() error {
	// 1. Connect plain TCP
	conn, err := net.Dial("tcp", net.JoinHostPort(s.config.Host, fmt.Sprintf("%d", s.config.Port)))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	// Greeting
	greeting, err := readSMTPReply(r)
	if err != nil {
		return fmt.Errorf("read greeting failed: %w", err)
	}
	fmt.Print("S: ", greeting)

	// 2. EHLO
	fmt.Fprintf(conn, "EHLO localhost\r\n")
	ehlo, err := readSMTPReply(r)
	if err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}
	fmt.Print("S: ", ehlo)

	// 3. STARTTLS
	fmt.Fprintf(conn, "STARTTLS\r\n")
	starttls, err := readSMTPReply(r)
	if err != nil {
		return fmt.Errorf("STARTTLS failed: %w", err)
	}
	fmt.Print("S: ", starttls)

	if !strings.HasPrefix(starttls, "220") {
		return fmt.Errorf("server rejected STARTTLS: %s", strings.TrimSpace(starttls))
	}

	// 4. Wrap in TLS
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         s.config.Host,
		InsecureSkipVerify: false,
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	// 5. Validate cert
	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates

	for i, cert := range certs {
		fmt.Printf("Cert %d: CN=%s, Issuer=%s\n", i, cert.Subject.CommonName, cert.Issuer.CommonName)
		fmt.Printf("  Valid: %s → %s\n", cert.NotBefore, cert.NotAfter)
		if time.Now().After(cert.NotAfter) {
			return fmt.Errorf("certificate expired on %s", cert.NotAfter)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         nil, // system root pool
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

type SMTP_SSL struct {
	config CheckConfig
}

func (s *SMTP_SSL) Run() error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", s.config.Host, s.config.Port), tlsConfig)
	if err != nil {
		return fmt.Errorf("server doesn't support SSL certificate err: %s", err.Error())
	}
	defer conn.Close()

	err = conn.VerifyHostname(s.config.Host)
	if err != nil {
		return fmt.Errorf("hostname doesn't match with certificate: %s", err.Error())
	}
	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	// fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))
	// check expiry
	if time.Now().After(expiry) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}
