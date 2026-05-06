package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/NonsoAmadi10/lnd-hardening-toolkit/pkg/scanner"
)

// TableWriter renders a human-readable table report to the given writer.
func TableWriter(w io.Writer, r *scanner.Report, useColor bool) {
	divider := strings.Repeat("━", 40)

	fmt.Fprintf(w, "⚡ LND Hardening Toolkit\n")
	fmt.Fprintf(w, "%s\n\n", divider)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "  No findings — your node looks good!\n\n")
	}

	// Group findings by module
	modules := groupByModule(r.Findings)
	for _, mod := range moduleOrder(modules) {
		findings := modules[mod]
		header := fmt.Sprintf("── %s ", formatModuleName(mod))
		header += strings.Repeat("─", max(0, 50-len(header)))
		fmt.Fprintf(w, "%s\n\n", header)

		for _, f := range findings {
			icon := severityIcon(f.Severity, useColor)
			label := severityLabel(f.Severity, useColor)
			fmt.Fprintf(w, "  %s %-5s  %s\n", icon, label, f.Title)
			if f.Remediation != "" {
				fmt.Fprintf(w, "  %s        → %s\n", strings.Repeat(" ", len(icon)-len(stripAnsi(icon))), f.Remediation)
			}
			fmt.Fprintln(w)
		}
	}

	// Score summary
	score := r.Score()
	rating := r.Rating()
	summary := r.Summary()

	fmt.Fprintf(w, "%s\n", divider)
	fmt.Fprintf(w, "Score: %d/100 %s %s\n", score, rating.Emoji(), rating.Label())
	fmt.Fprintf(w, "  %d critical · %d high · %d medium · %d low · %d info\n",
		summary[scanner.Critical],
		summary[scanner.High],
		summary[scanner.Medium],
		summary[scanner.Low],
		summary[scanner.Info],
	)
}

// JSONOutput holds the structured JSON output.
type JSONOutput struct {
	Score    int               `json:"score"`
	Rating  string            `json:"rating"`
	Summary map[string]int    `json:"summary"`
	Findings []jsonFinding    `json:"findings"`
}

type jsonFinding struct {
	ID          string `json:"id"`
	Module      string `json:"module"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Reference   string `json:"reference,omitempty"`
}

// JSONWriter renders a machine-readable JSON report to the given writer.
func JSONWriter(w io.Writer, r *scanner.Report) error {
	summary := r.Summary()
	out := JSONOutput{
		Score:  r.Score(),
		Rating: string(r.Rating()),
		Summary: map[string]int{
			"critical": summary[scanner.Critical],
			"high":     summary[scanner.High],
			"medium":   summary[scanner.Medium],
			"low":      summary[scanner.Low],
			"info":     summary[scanner.Info],
		},
	}

	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			ID:          f.ID,
			Module:      f.Module,
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			Remediation: f.Remediation,
			Reference:   f.Reference,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func groupByModule(findings []scanner.Finding) map[string][]scanner.Finding {
	groups := make(map[string][]scanner.Finding)
	for _, f := range findings {
		groups[f.Module] = append(groups[f.Module], f)
	}
	return groups
}

// moduleOrder returns modules in a consistent display order.
func moduleOrder(groups map[string][]scanner.Finding) []string {
	order := []string{"transport", "keys", "channels", "access", "privacy", "hygiene"}
	var result []string
	for _, m := range order {
		if _, ok := groups[m]; ok {
			result = append(result, m)
		}
	}
	// Append any modules not in the predefined order
	for m := range groups {
		found := false
		for _, o := range order {
			if m == o {
				found = true
				break
			}
		}
		if !found {
			result = append(result, m)
		}
	}
	return result
}

func formatModuleName(mod string) string {
	names := map[string]string{
		"transport": "Transport Security",
		"keys":      "Key Management",
		"channels":  "Channel Safety",
		"access":    "Access Control",
		"privacy":   "Network Privacy",
		"hygiene":   "Node Hygiene",
	}
	if name, ok := names[mod]; ok {
		return name
	}
	return strings.Title(mod)
}

func severityIcon(s scanner.Severity, color bool) string {
	switch s {
	case scanner.Critical:
		return "🔴"
	case scanner.High:
		return "🟡"
	case scanner.Medium:
		return "🟡"
	case scanner.Low:
		return "🔵"
	case scanner.Info:
		return "✅"
	default:
		return "❓"
	}
}

func severityLabel(s scanner.Severity, color bool) string {
	if !color {
		return s.String()
	}
	// ANSI colors for terminal output
	switch s {
	case scanner.Critical:
		return "\033[91m" + s.String() + "\033[0m"
	case scanner.High:
		return "\033[93m" + s.String() + "\033[0m"
	case scanner.Medium:
		return "\033[33m" + s.String() + "\033[0m"
	case scanner.Low:
		return "\033[94m" + s.String() + "\033[0m"
	case scanner.Info:
		return "\033[92m" + s.String() + "\033[0m"
	default:
		return s.String()
	}
}

func stripAnsi(s string) string {
	// Simple strip for length calculation
	result := s
	for strings.Contains(result, "\033[") {
		start := strings.Index(result, "\033[")
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
