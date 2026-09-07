package report

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription,omitempty"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Help             sarifMessage        `json:"help,omitempty"`
	Properties       *sarifRulePropertys `json:"properties,omitempty"`
}

type sarifRulePropertys struct {
	Module    string   `json:"module,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          *sarifResultProperty `json:"properties,omitempty"`
}

type sarifResultProperty struct {
	Module      string `json:"module,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                    `json:"executionSuccessful"`
	Properties          *sarifInvocationDetails `json:"properties,omitempty"`
}

type sarifInvocationDetails struct {
	Score   int            `json:"score"`
	Rating  string         `json:"rating"`
	Summary map[string]int `json:"summary"`
}

var channelIDPattern = regexp.MustCompile(`(?i)\bchannel\s+(\d+)\b`)

// SARIFWriter renders findings in SARIF 2.1.0 format.
func SARIFWriter(w io.Writer, r *scanner.Report) error {
	return SARIFWriterWithScore(w, r, r.Score(), r.Rating(), r.Summary())
}

// SARIFWriterWithScore renders SARIF output with externally provided scoring.
func SARIFWriterWithScore(w io.Writer, r *scanner.Report, score int, rating scanner.Rating, summary map[scanner.Severity]int) error {
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "lnaudit",
					InformationURI: "https://github.com/0xciph3r/lnaudit",
					Rules:          sarifRulesFromFindings(r.Findings),
				},
			},
			Results: sarifResultsFromFindings(r.Findings),
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				Properties: &sarifInvocationDetails{
					Score:  score,
					Rating: string(rating),
					Summary: map[string]int{
						"critical": summary[scanner.Critical],
						"high":     summary[scanner.High],
						"medium":   summary[scanner.Medium],
						"low":      summary[scanner.Low],
						"info":     summary[scanner.Info],
					},
				},
			}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifRulesFromFindings(findings []scanner.Finding) []sarifRule {
	byID := make(map[string]scanner.Finding)
	for _, f := range findings {
		if _, exists := byID[f.ID]; !exists {
			byID[f.ID] = f
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		f := byID[id]
		rule := sarifRule{
			ID:               f.ID,
			ShortDescription: sarifMessage{Text: sarifRuleTitle(f.Title)},
			FullDescription:  sarifMessage{Text: firstNonEmpty(f.Description, f.Title)},
			Help:             sarifMessage{Text: firstNonEmpty(f.Remediation, "Review this finding and apply least-privilege hardening.")},
			Properties: &sarifRulePropertys{
				Module:    f.Module,
				Severity:  strings.ToLower(f.Severity.String()),
				Tags:      []string{"module:" + f.Module, "severity:" + strings.ToLower(f.Severity.String())},
				Reference: f.Reference,
			},
		}
		// Encode default severity as a stable tag for SARIF consumers.
		rule.Properties.Tags = append(rule.Properties.Tags, "default-level:"+sarifLevelForSeverity(f.Severity))
		rules = append(rules, rule)
	}
	return rules
}

func sarifResultsFromFindings(findings []scanner.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		msg := f.Title
		if f.Description != "" {
			msg = fmt.Sprintf("%s — %s", f.Title, f.Description)
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevelForSeverity(f.Severity),
			Message: sarifMessage{Text: msg},
			PartialFingerprints: map[string]string{
				"lnaudit/finding-key": sarifStableFingerprint(f),
			},
			Properties: &sarifResultProperty{
				Module:      f.Module,
				Severity:    strings.ToLower(f.Severity.String()),
				Remediation: f.Remediation,
				Reference:   f.Reference,
			},
		})
	}
	return results
}

func sarifLevelForSeverity(sev scanner.Severity) string {
	switch sev {
	case scanner.Critical, scanner.High:
		return "error"
	case scanner.Medium:
		return "warning"
	case scanner.Low:
		return "note"
	default:
		return "note"
	}
}

func sarifStableFingerprint(f scanner.Finding) string {
	instanceKey := sarifInstanceKey(f)
	raw := strings.Join([]string{
		f.ID,
		f.Module,
		instanceKey,
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func sarifInstanceKey(f scanner.Finding) string {
	title := strings.TrimSpace(f.Title)
	m := channelIDPattern.FindStringSubmatch(title)
	if len(m) == 2 {
		return "channel:" + m[1]
	}
	return ""
}

func sarifRuleTitle(title string) string {
	if title == "" {
		return title
	}
	return channelIDPattern.ReplaceAllString(title, "Channel <id>")
}

func firstNonEmpty(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}
