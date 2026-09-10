package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/jamming"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

// JammingJSONOutput is the machine-readable output schema for jamming analysis.
type JammingJSONOutput struct {
	Score    int                  `json:"score"`
	Rating   string               `json:"rating"`
	Summary  map[string]int       `json:"summary"`
	Findings []jammingJSONFinding `json:"findings"`
}

type jammingJSONFinding struct {
	ID          string                 `json:"id"`
	Class       string                 `json:"class"`
	Severity    string                 `json:"severity"`
	Confidence  string                 `json:"confidence,omitempty"`
	ChannelID   uint64                 `json:"channel_id,omitempty"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
}

// JammingTableWriter renders a human-readable report for jamming findings.
func JammingTableWriter(w io.Writer, findings []jamming.Finding, useColor bool) {
	score := JammingScore(findings)
	rating := JammingRating(findings)
	summary := JammingSummary(findings)
	JammingTableWriterWithScore(w, findings, score, rating, summary, useColor)
}

// JammingJSONWriter renders jamming findings as JSON.
func JammingJSONWriter(w io.Writer, findings []jamming.Finding) error {
	score := JammingScore(findings)
	rating := JammingRating(findings)
	summary := JammingSummaryStrings(findings)
	return JammingJSONWriterWithScore(w, findings, score, rating, summary)
}

// JammingJSONWriterWithScore renders jamming findings as JSON using external scoring.
func JammingJSONWriterWithScore(w io.Writer, findings []jamming.Finding, score int, rating scanner.Rating, summary map[string]int) error {
	out := JammingJSONOutput{
		Score:    score,
		Rating:   string(rating),
		Summary:  summary,
		Findings: make([]jammingJSONFinding, 0, len(findings)),
	}

	for _, finding := range findings {
		out.Findings = append(out.Findings, jammingJSONFinding{
			ID:          finding.ID,
			Class:       string(finding.Class),
			Severity:    finding.Severity.String(),
			Confidence:  string(finding.Confidence),
			ChannelID:   finding.ChannelID,
			Title:       finding.Title,
			Description: finding.Description,
			Evidence:    finding.Evidence,
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// JammingSARIFWriter renders jamming findings as SARIF 2.1.0.
func JammingSARIFWriter(w io.Writer, findings []jamming.Finding) error {
	score := JammingScore(findings)
	rating := JammingRating(findings)
	summary := JammingSummaryStrings(findings)
	return JammingSARIFWriterWithScore(w, findings, score, rating, summary)
}

// JammingSARIFWriterWithScore renders SARIF with externally provided scoring.
func JammingSARIFWriterWithScore(w io.Writer, findings []jamming.Finding, score int, rating scanner.Rating, summary map[string]int) error {
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "lnaudit",
					InformationURI: "https://github.com/0xciph3r/lnaudit",
					Rules:          sarifRulesFromJammingFindings(findings),
				},
			},
			Results: sarifResultsFromJammingFindings(findings),
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				Properties: &sarifInvocationDetails{
					Score:   score,
					Rating:  string(rating),
					Summary: summary,
				},
			}},
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

// JammingScore computes a report score compatible with scanner severity scoring.
func JammingScore(findings []jamming.Finding) int {
	score := 100
	for _, finding := range findings {
		score -= finding.Severity.Points()
	}
	if score < 0 {
		return 0
	}
	return score
}

// JammingRating computes the rating for jamming findings.
func JammingRating(findings []jamming.Finding) scanner.Rating {
	score := JammingScore(findings)
	switch {
	case score >= 90:
		return scanner.RatingHardened
	case score >= 70:
		return scanner.RatingAcceptable
	case score >= 40:
		return scanner.RatingNeedsWork
	default:
		return scanner.RatingCriticalRisk
	}
}

// JammingSummary returns per-severity counts for jamming findings.
func JammingSummary(findings []jamming.Finding) map[scanner.Severity]int {
	summary := map[scanner.Severity]int{
		scanner.Critical: 0,
		scanner.High:     0,
		scanner.Medium:   0,
		scanner.Low:      0,
		scanner.Info:     0,
	}
	for _, finding := range findings {
		summary[finding.Severity]++
	}
	return summary
}

// JammingSummaryStrings returns per-severity counts keyed for JSON output.
func JammingSummaryStrings(findings []jamming.Finding) map[string]int {
	summary := JammingSummary(findings)
	return map[string]int{
		"critical": summary[scanner.Critical],
		"high":     summary[scanner.High],
		"medium":   summary[scanner.Medium],
		"low":      summary[scanner.Low],
		"info":     summary[scanner.Info],
	}
}

// JammingTableWriterWithScore renders a table report using externally provided scoring.
func JammingTableWriterWithScore(
	w io.Writer,
	findings []jamming.Finding,
	score int,
	rating scanner.Rating,
	summary map[scanner.Severity]int,
	useColor bool,
) {
	report := jammingReportFromFindings(findings)
	TableWriterWithScore(w, report, score, rating, summary, useColor)
}

func jammingReportFromFindings(findings []jamming.Finding) *scanner.Report {
	r := &scanner.Report{}
	for _, finding := range findings {
		title := finding.Title
		if finding.Confidence != "" {
			title = fmt.Sprintf("%s [%s]", finding.Title, strings.ToUpper(string(finding.Confidence)))
		}

		r.Add(scanner.Finding{
			ID:          finding.ID,
			Module:      "jamming",
			Severity:    finding.Severity,
			Title:       title,
			Description: finding.Description,
			Remediation: jammingRemediation(finding),
		})
	}
	return r
}

func jammingRemediation(finding jamming.Finding) string {
	if finding.ChannelID == 0 {
		return "Review sustained pressure signals and tighten HTLC policy where appropriate."
	}
	return fmt.Sprintf("Review channel %d pressure over time and tighten HTLC policy where appropriate.", finding.ChannelID)
}

func sarifRulesFromJammingFindings(findings []jamming.Finding) []sarifRule {
	byID := make(map[string]jamming.Finding)
	for _, finding := range findings {
		if _, exists := byID[finding.ID]; !exists {
			byID[finding.ID] = finding
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		finding := byID[id]
		rules = append(rules, sarifRule{
			ID:               finding.ID,
			ShortDescription: sarifMessage{Text: sarifRuleTitle(finding.Title)},
			FullDescription:  sarifMessage{Text: finding.Description},
			Help:             sarifMessage{Text: jammingRemediation(finding)},
			Properties: &sarifRuleProperties{
				Module:   "jamming",
				Severity: strings.ToLower(finding.Severity.String()),
				Tags: []string{
					"module:jamming",
					"severity:" + strings.ToLower(finding.Severity.String()),
					"class:" + string(finding.Class),
				},
			},
		})
	}
	return rules
}

func sarifResultsFromJammingFindings(findings []jamming.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		message := finding.Title
		if finding.Description != "" {
			message = fmt.Sprintf("%s — %s", finding.Title, finding.Description)
		}

		fingerprint := fmt.Sprintf("%s|channel:%d|class:%s", finding.ID, finding.ChannelID, finding.Class)
		results = append(results, sarifResult{
			RuleID:  finding.ID,
			Level:   sarifLevelForSeverity(finding.Severity),
			Message: sarifMessage{Text: message},
			PartialFingerprints: map[string]string{
				"lnaudit/finding-key": stableHash(fingerprint),
			},
			Properties: &sarifResultProperty{
				Module:      "jamming",
				Severity:    strings.ToLower(finding.Severity.String()),
				Remediation: jammingRemediation(finding),
				Confidence:  string(finding.Confidence),
				Evidence:    finding.Evidence,
			},
		})
	}
	return results
}
