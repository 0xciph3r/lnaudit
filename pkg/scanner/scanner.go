package scanner

import "fmt"

// Severity represents the impact level of a security finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Points returns the score deduction for this severity level.
func (s Severity) Points() int {
	switch s {
	case Critical:
		return 15
	case High:
		return 10
	case Medium:
		return 5
	case Low:
		return 2
	case Info:
		return 0
	default:
		return 0
	}
}

// ParseSeverity converts a string to a Severity level.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info", "INFO":
		return Info, nil
	case "low", "LOW":
		return Low, nil
	case "medium", "MEDIUM", "med", "MED":
		return Medium, nil
	case "high", "HIGH":
		return High, nil
	case "critical", "CRITICAL", "crit", "CRIT":
		return Critical, nil
	default:
		return Info, fmt.Errorf("unknown severity: %q", s)
	}
}

// Finding represents a single security check result.
type Finding struct {
	ID          string   `json:"id"`
	Module      string   `json:"module"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Reference   string   `json:"reference,omitempty"`
}

// Rating describes the overall security posture of the node.
type Rating string

const (
	RatingHardened     Rating = "hardened"
	RatingAcceptable   Rating = "acceptable"
	RatingNeedsWork    Rating = "needs_hardening"
	RatingCriticalRisk Rating = "critical_risk"
)

func (r Rating) Emoji() string {
	switch r {
	case RatingHardened:
		return "🟢"
	case RatingAcceptable:
		return "🟡"
	case RatingNeedsWork:
		return "🟠"
	case RatingCriticalRisk:
		return "🔴"
	default:
		return "❓"
	}
}

func (r Rating) Label() string {
	switch r {
	case RatingHardened:
		return "Hardened"
	case RatingAcceptable:
		return "Acceptable"
	case RatingNeedsWork:
		return "Needs Hardening"
	case RatingCriticalRisk:
		return "Critical Risk"
	default:
		return "Unknown"
	}
}

// Report aggregates all findings from a scan and computes the overall score.
type Report struct {
	Findings []Finding `json:"findings"`
}

// Score computes the security score (0–100) by deducting points for each finding.
func (r *Report) Score() int {
	score := 100
	for _, f := range r.Findings {
		score -= f.Severity.Points()
	}
	if score < 0 {
		score = 0
	}
	return score
}

// Rating returns the overall security rating based on the score.
func (r *Report) Rating() Rating {
	s := r.Score()
	switch {
	case s >= 90:
		return RatingHardened
	case s >= 70:
		return RatingAcceptable
	case s >= 40:
		return RatingNeedsWork
	default:
		return RatingCriticalRisk
	}
}

// Summary returns counts of findings by severity level.
func (r *Report) Summary() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// HasFindingsAtOrAbove returns true if any finding meets or exceeds the given severity.
func (r *Report) HasFindingsAtOrAbove(threshold Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

// Add appends a finding to the report.
func (r *Report) Add(f Finding) {
	r.Findings = append(r.Findings, f)
}
