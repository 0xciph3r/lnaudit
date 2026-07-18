package confgen

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

// Suggestion is a config key/value recommendation derived from findings.
type Suggestion struct {
	Key    string
	Value  string
	Reason string
}

// SuggestResult contains suggested config entries and manual actions.
type SuggestResult struct {
	Suggestions   []Suggestion
	ManualActions []string
}

// SuggestFromFindings maps findings into config suggestions and manual actions.
func SuggestFromFindings(findings []scanner.Finding) SuggestResult {
	suggestionByKey := make(map[string]Suggestion)
	manualSet := make(map[string]bool)

	add := func(key, value, reason string) {
		if existing, ok := suggestionByKey[key]; ok {
			// Keep the first deterministic value; append reason context.
			if !strings.Contains(existing.Reason, reason) {
				existing.Reason += "; " + reason
				suggestionByKey[key] = existing
			}
			return
		}
		suggestionByKey[key] = Suggestion{Key: key, Value: value, Reason: reason}
	}
	addManual := func(action string) {
		if action != "" {
			manualSet[action] = true
		}
	}

	for _, f := range findings {
		switch f.ID {
		case "A-1":
			add("no-macaroons", "false", "restore macaroon authentication")
		case "A-4":
			addManual("Replace admin.macaroon with readonly.macaroon for read-only integrations.")
		case "A-5":
			addManual("Replace admin.macaroon with invoice.macaroon for invoice-only integrations.")
		case "A-6":
			addManual("Bake and deploy a custom-scoped macaroon for integrations that do not need full admin rights.")
		case "C-1":
			add("wtclient.active", "true", "enable watchtower client")
			addManual("Set wtclient.private-tower-uris=<pubkey>@<host>:<port> for at least one reachable watchtower.")
		case "C-2":
			add("bitcoin.defaultchanconfs", "3", "increase channel funding confirmation depth")
		case "C-4":
			add("maxchansize", "16777215", "set explicit max channel size")
		case "C-5":
			add("maxpendingchannels", "1", "set explicit pending channel limit")
		case "H-4":
			add("debuglevel", "info", "disable verbose production logging")
		case "H-4b":
			add("debughtlc", "false", "disable HTLC debug mode")
		case "H-6b":
			add("noencryptwallet", "false", "keep wallet encrypted at rest")
		case "H-6c":
			add("trickledelay", "5000", "restore default anti-timing delay")
		case "H-6d":
			add("unsafe-disconnect", "false", "avoid unsafe peer disconnect behavior")
		case "H-7a":
			addManual("Rotate TLS keypair if tls.key was copied outside controlled directories.")
		case "H-7b":
			addManual("Move seed material to offline secure storage and remove plaintext seed files.")
		case "H-7c", "H-7d":
			addManual("Move sensitive .env credentials to a secret manager and rotate exposed keys.")
		case "K-2":
			add("tor.encryptkey", "true", "encrypt onion private key at rest")
		case "N-1":
			add("tor.skip-proxy-for-clearnet-targets", "false", "prevent Tor bypass")
		case "N-1b":
			add("tor.v3", "true", "use modern onion service keys")
		case "N-2":
			add("tor.streamisolation", "true", "isolate Tor circuits per peer")
		case "N-3":
			add("protocol.option-scid-alias", "true", "reduce channel UTXO linkage")
		case "N-4", "T-3":
			add("rpclisten", "127.0.0.1:10009", "bind gRPC to loopback")
		case "N-5", "T-3b":
			add("restlisten", "127.0.0.1:8080", "bind REST to loopback")
		case "P-1":
			add("allow-circular-route", "false", "reduce balance-probing risk")
		case "P-2":
			add("rejectpush", "true", "reject push-amount channels")
		case "P-3":
			add("default-remote-max-htlcs", "30", "limit channel jamming exposure")
		case "P-4":
			add("enable-upfront-shutdown", "true", "fix cooperative close payout script")
		case "P-5":
			add("max-cltv-expiry", "2016", "cap long CLTV lockups")
		case "P-6":
			add("minchansize", "20000", "raise minimum channel size")
		case "P-7":
			add("bitcoin.timelockdelta", "80", "improve on-chain reaction buffer")
		case "P-8":
			add("bitcoin.minhtlc", "1000", "raise spam cost floor")
		case "P-9":
			add("bitcoin.estimatemode", "CONSERVATIVE", "use conservative fee estimation")
		case "P-12":
			add("requireinterceptor", "false", "avoid interceptor-driven payment DoS")
		case "P-13":
			addManual("Remove restcors=* and restrict REST CORS to explicit trusted origins only.")
		case "R-1":
			add("protocol.zero-conf", "false", "disable zero-conf channels by default")
		case "R-2":
			add("protocol.no-anchors", "false", "keep anchor channel support")
		case "R-3":
			add("protocol.wumbo-channels", "false", "avoid oversized channel blast radius")
		case "R-4":
			add("autopilot.active", "false", "disable automatic channel deployment")
		case "R-5":
			add("gossip.ban-threshold", "100", "restore gossip peer banning")
		case "R-6":
			add("no-rest-tls", "false", "keep REST TLS enabled")
		case "R-7":
			add("tlsencryptkey", "true", "encrypt TLS private key")
		case "R-8":
			add("wallet-unlock-allow-create", "false", "prevent wallet injection at startup")
		case "T-5":
			addManual("If running Tor-only, remove clearnet externalip entries from lnd.conf.")
		}
	}

	suggestions := make([]Suggestion, 0, len(suggestionByKey))
	for _, s := range suggestionByKey {
		suggestions = append(suggestions, s)
	}
	sort.Slice(suggestions, func(i, j int) bool {
		si := sectionForKey(suggestions[i].Key)
		sj := sectionForKey(suggestions[j].Key)
		if si == sj {
			return suggestions[i].Key < suggestions[j].Key
		}
		return si < sj
	})

	manual := make([]string, 0, len(manualSet))
	for m := range manualSet {
		manual = append(manual, m)
	}
	sort.Strings(manual)

	return SuggestResult{
		Suggestions:   suggestions,
		ManualActions: manual,
	}
}

// WriteSuggestedConfigPatch writes suggested lnd.conf entries derived from findings.
func WriteSuggestedConfigPatch(w io.Writer, findings []scanner.Finding) error {
	result := SuggestFromFindings(findings)
	if len(result.Suggestions) == 0 && len(result.ManualActions) == 0 {
		_, err := fmt.Fprintln(w, "# No config suggestions derived from current findings.")
		return err
	}

	if _, err := fmt.Fprintln(w, "# lnaudit suggest-config output"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# Review before applying to production lnd.conf"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	grouped := make(map[string][]Suggestion)
	var sectionOrder []string
	for _, s := range result.Suggestions {
		sec := sectionForKey(s.Key)
		if _, ok := grouped[sec]; !ok {
			sectionOrder = append(sectionOrder, sec)
		}
		grouped[sec] = append(grouped[sec], s)
	}
	sort.Strings(sectionOrder)

	for i, sec := range sectionOrder {
		if _, err := fmt.Fprintf(w, "[%s]\n", sec); err != nil {
			return err
		}
		for _, s := range grouped[sec] {
			if _, err := fmt.Fprintf(w, "%s=%s\n", s.Key, s.Value); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "# reason: %s\n", s.Reason); err != nil {
				return err
			}
		}
		if i < len(sectionOrder)-1 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}

	if len(result.ManualActions) > 0 {
		if _, err := fmt.Fprintln(w, "\n# Manual actions (not direct lnd.conf key updates):"); err != nil {
			return err
		}
		for _, m := range result.ManualActions {
			if _, err := fmt.Fprintf(w, "# - %s\n", m); err != nil {
				return err
			}
		}
	}

	return nil
}

func sectionForKey(key string) string {
	switch {
	case strings.HasPrefix(key, "bitcoin."):
		return "Bitcoin"
	case strings.HasPrefix(key, "protocol.") || strings.HasPrefix(key, "autopilot.") || strings.HasPrefix(key, "gossip."):
		return "protocol"
	case strings.HasPrefix(key, "tor.") || key == "rpclisten" || key == "restlisten" || key == "no-rest-tls" || key == "tlsencryptkey":
		return "transport"
	case strings.HasPrefix(key, "wtclient."):
		return "wtclient"
	default:
		return "Application Options"
	}
}
