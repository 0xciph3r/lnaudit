package checks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/NonsoAmadi10/lnd-hardening-toolkit/pkg/config"
	"github.com/NonsoAmadi10/lnd-hardening-toolkit/pkg/scanner"
)

const (
	certExpiryWarnDays = 30
)

// CheckTLSCert audits the TLS certificate at the given path.
func CheckTLSCert(certPath string) []scanner.Finding {
	if certPath == "" {
		return nil
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []scanner.Finding{{
				ID:          "T-1",
				Module:      "transport",
				Severity:    scanner.Critical,
				Title:       "TLS certificate not found",
				Description: fmt.Sprintf("Expected tls.cert at %s but file does not exist.", certPath),
				Remediation: "Ensure LND has generated a TLS certificate, or check your tlscertpath setting.",
			}}
		}
		return nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return []scanner.Finding{{
			ID:          "T-1",
			Module:      "transport",
			Severity:    scanner.High,
			Title:       "TLS certificate is not valid PEM",
			Description: fmt.Sprintf("Cannot decode PEM from %s.", certPath),
			Remediation: "Delete tls.cert and tls.key, then restart LND to regenerate.",
		}}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []scanner.Finding{{
			ID:          "T-1",
			Module:      "transport",
			Severity:    scanner.High,
			Title:       "TLS certificate cannot be parsed",
			Description: fmt.Sprintf("x509 parse error: %v", err),
			Remediation: "Delete tls.cert and tls.key, then restart LND to regenerate.",
		}}
	}

	var findings []scanner.Finding
	now := time.Now()

	// Check expiry
	if now.After(cert.NotAfter) {
		findings = append(findings, scanner.Finding{
			ID:          "T-1a",
			Module:      "transport",
			Severity:    scanner.Critical,
			Title:       fmt.Sprintf("TLS certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
			Description: "An expired certificate will cause gRPC and REST connections to fail.",
			Remediation: "Delete tls.cert and tls.key, then restart LND to regenerate.",
		})
	} else {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft <= certExpiryWarnDays {
			findings = append(findings, scanner.Finding{
				ID:          "T-1a",
				Module:      "transport",
				Severity:    scanner.High,
				Title:       fmt.Sprintf("TLS certificate expires in %d days (%s)", daysLeft, cert.NotAfter.Format("2006-01-02")),
				Remediation: "Plan a certificate rotation before expiry. Delete tls.cert/tls.key and restart LND.",
			})
		}
	}

	// Check key type and size
	switch pub := cert.PublicKey.(type) {
	case interface{ Params() *interface{} }:
		_ = pub // fallback — unrecognized key type
	default:
		keyInfo := describePublicKey(cert)
		if keyInfo.weak {
			findings = append(findings, scanner.Finding{
				ID:          "T-2",
				Module:      "transport",
				Severity:    scanner.Medium,
				Title:       fmt.Sprintf("TLS certificate uses weak key: %s", keyInfo.desc),
				Remediation: "Regenerate with a stronger key (LND defaults to P-256 ECDSA or Ed25519).",
			})
		}
	}

	// Check signature algorithm
	if isWeakSigAlg(cert.SignatureAlgorithm) {
		findings = append(findings, scanner.Finding{
			ID:          "T-2b",
			Module:      "transport",
			Severity:    scanner.Medium,
			Title:       fmt.Sprintf("TLS certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm),
			Remediation: "Regenerate the TLS certificate — LND should use SHA-256 or better by default.",
		})
	}

	return findings
}

type keyDescriptor struct {
	desc string
	weak bool
}

func describePublicKey(cert *x509.Certificate) keyDescriptor {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// RSA < 2048 is weak
		if cert.PublicKey != nil {
			// Use the bit length from the key
			type rsaKey interface {
				Size() int
			}
			if rsa, ok := cert.PublicKey.(rsaKey); ok {
				bits := rsa.Size() * 8
				if bits < 2048 {
					return keyDescriptor{fmt.Sprintf("RSA-%d", bits), true}
				}
				return keyDescriptor{fmt.Sprintf("RSA-%d", bits), false}
			}
		}
		return keyDescriptor{"RSA (unknown size)", false}
	case x509.ECDSA:
		return keyDescriptor{"ECDSA", false}
	case x509.Ed25519:
		return keyDescriptor{"Ed25519", false}
	default:
		return keyDescriptor{cert.PublicKeyAlgorithm.String(), false}
	}
}

func isWeakSigAlg(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// CheckRPCBindAddress audits the rpclisten and restlisten bind addresses.
func CheckRPCBindAddress(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	for _, addr := range cfg.RPCListeners {
		if isBoundToAllInterfaces(addr) {
			findings = append(findings, scanner.Finding{
				ID:          "T-3",
				Module:      "transport",
				Severity:    scanner.Critical,
				Title:       fmt.Sprintf("gRPC bound to all interfaces: %s", addr),
				Description: "The gRPC control plane is exposed to all network interfaces, including the public internet.",
				Remediation: "Change rpclisten to 127.0.0.1:10009 in lnd.conf",
			})
		}
	}

	for _, addr := range cfg.RESTListeners {
		if isBoundToAllInterfaces(addr) {
			findings = append(findings, scanner.Finding{
				ID:          "T-3b",
				Module:      "transport",
				Severity:    scanner.Critical,
				Title:       fmt.Sprintf("REST API bound to all interfaces: %s", addr),
				Description: "The REST API is exposed to all network interfaces.",
				Remediation: "Change restlisten to 127.0.0.1:8080 in lnd.conf",
			})
		}
	}

	return findings
}

// CheckExternalIPLeak detects when a clearnet IP is advertised alongside Tor.
func CheckExternalIPLeak(cfg *config.LndConfig) []scanner.Finding {
	if !cfg.Tor.Active {
		return nil
	}

	var clearnetIPs []string
	for _, ip := range cfg.ExternalIPs {
		if !isOnionAddress(ip) {
			clearnetIPs = append(clearnetIPs, ip)
		}
	}

	if len(clearnetIPs) > 0 {
		return []scanner.Finding{{
			ID:       "T-5",
			Module:   "transport",
			Severity: scanner.High,
			Title:    fmt.Sprintf("Clearnet IP advertised alongside Tor: %s", strings.Join(clearnetIPs, ", ")),
			Description: "Your node advertises a clearnet IP while Tor is active. " +
				"This reveals your node's physical location and defeats the purpose of Tor.",
			Remediation: "Remove externalip= entries from lnd.conf if you intend to be Tor-only.",
		}}
	}

	return nil
}

func isBoundToAllInterfaces(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Might be just a port like ":10009"
		if strings.HasPrefix(addr, ":") {
			return true
		}
		return false
	}
	return host == "" || host == "0.0.0.0" || host == "::"
}

func isOnionAddress(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return strings.HasSuffix(strings.ToLower(host), ".onion")
}
