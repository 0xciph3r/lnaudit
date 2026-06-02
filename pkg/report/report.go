package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// newRenderer returns a lipgloss renderer appropriate for the output target.
func newRenderer(useColor bool) *lipgloss.Renderer {
	if !useColor {
		r := lipgloss.NewRenderer(os.Stdout)
		r.SetColorProfile(termenv.Ascii)
		return r
	}
	return lipgloss.DefaultRenderer()
}

// TableWriter renders a human-readable table report to the given writer.
func TableWriter(w io.Writer, r *scanner.Report, useColor bool) {
	TableWriterWithScore(w, r, r.Score(), r.Rating(), r.Summary(), useColor)
}

// TableWriterWithScore renders a table report using externally provided score values.
func TableWriterWithScore(w io.Writer, r *scanner.Report, score int, rating scanner.Rating, summary map[scanner.Severity]int, useColor bool) {
	re := newRenderer(useColor)

	// Styles
	headerStyle := re.NewStyle().Bold(true).Foreground(lipgloss.Color("#F7FAFC"))
	dividerStyle := re.NewStyle().Foreground(lipgloss.Color("#3A4556"))
	moduleStyle := re.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D9FF"))
	descStyle := re.NewStyle().Foreground(lipgloss.Color("#8B97AA"))
	recoLabelStyle := re.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981"))
	recoStyle := re.NewStyle().Foreground(lipgloss.Color("#D1FAE5"))
	refStyle := re.NewStyle().Foreground(lipgloss.Color("#6366F1")).Italic(true)
	scoreStyle := re.NewStyle().Bold(true)
	summaryStyle := re.NewStyle().Foreground(lipgloss.Color("#8B97AA"))
	passStyle := re.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981"))

	topDivider := dividerStyle.Render(strings.Repeat("━", 60))
	thinDivider := dividerStyle.Render(strings.Repeat("─", 60))

	// Header
	fmt.Fprintf(w, "\n%s\n", topDivider)
	fmt.Fprintf(w, " %s\n", headerStyle.Render("lnaudit — Security Audit Report"))
	fmt.Fprintf(w, "%s\n", topDivider)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "\n  %s\n\n", passStyle.Render("No findings — your node looks good!"))
		writeScore(w, score, rating, summary, scoreStyle, summaryStyle, topDivider, re)
		return
	}

	// Group findings by module
	modules := groupByModule(r.Findings)
	for _, mod := range moduleOrder(modules) {
		findings := modules[mod]

		fmt.Fprintf(w, "\n %s %s\n",
			moduleStyle.Render("■"),
			moduleStyle.Render(formatModuleName(mod)),
		)
		fmt.Fprintf(w, " %s\n", thinDivider)

		for i, f := range findings {
			sevLabel := severityLabel(f.Severity, re)

			// Title line
			fmt.Fprintf(w, "\n  %s  %s\n", sevLabel, headerStyle.Render(f.Title))

			// Description
			if f.Description != "" {
				wrapped := wrapText(f.Description, 56)
				for _, line := range strings.Split(wrapped, "\n") {
					fmt.Fprintf(w, "      %s\n", descStyle.Render(line))
				}
			}

			// Recommendation
			if f.Remediation != "" {
				fmt.Fprintf(w, "\n      %s\n", recoLabelStyle.Render("Recommendation:"))
				wrapped := wrapText(f.Remediation, 54)
				for _, line := range strings.Split(wrapped, "\n") {
					fmt.Fprintf(w, "        %s\n", recoStyle.Render(line))
				}
			}

			// Reference
			if f.Reference != "" {
				fmt.Fprintf(w, "      %s\n", refStyle.Render("Ref: "+f.Reference))
			}

			// Separator between findings in same module
			if i < len(findings)-1 {
				fmt.Fprintln(w)
			}
		}
		fmt.Fprintln(w)
	}

	writeScore(w, score, rating, summary, scoreStyle, summaryStyle, topDivider, re)
}

func writeScore(w io.Writer, score int, rating scanner.Rating, summary map[scanner.Severity]int, scoreStyle, summaryStyle lipgloss.Style, topDivider string, re *lipgloss.Renderer) {
	var ratingStyle lipgloss.Style
	switch rating {
	case scanner.RatingHardened:
		ratingStyle = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981"))
	case scanner.RatingAcceptable:
		ratingStyle = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#F59E0B"))
	case scanner.RatingNeedsWork:
		ratingStyle = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#F97316"))
	case scanner.RatingCriticalRisk:
		ratingStyle = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444"))
	default:
		ratingStyle = scoreStyle
	}

	fmt.Fprintf(w, "%s\n", topDivider)
	fmt.Fprintf(w, " Score: %s  %s\n",
		scoreStyle.Render(fmt.Sprintf("%d/100", score)),
		ratingStyle.Render(rating.Label()),
	)
	fmt.Fprintf(w, " %s\n",
		summaryStyle.Render(fmt.Sprintf(
			"%d critical · %d high · %d medium · %d low · %d info",
			summary[scanner.Critical],
			summary[scanner.High],
			summary[scanner.Medium],
			summary[scanner.Low],
			summary[scanner.Info],
		)),
	)
	fmt.Fprintf(w, "%s\n\n", topDivider)
}

func severityLabel(s scanner.Severity, re *lipgloss.Renderer) string {
	var style lipgloss.Style
	switch s {
	case scanner.Critical:
		style = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444"))
	case scanner.High:
		style = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#F59E0B"))
	case scanner.Medium:
		style = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#F97316"))
	case scanner.Low:
		style = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#3B82F6"))
	case scanner.Info:
		style = re.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981"))
	default:
		style = re.NewStyle()
	}
	// Pad to fixed width for alignment
	return style.Render(fmt.Sprintf("%-8s", s.String()))
}

// wrapText wraps a string to the given width at word boundaries.
func wrapText(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	current := words[0]

	for _, w := range words[1:] {
		if len(current)+1+len(w) > width {
			lines = append(lines, current)
			current = w
		} else {
			current += " " + w
		}
	}
	lines = append(lines, current)
	return strings.Join(lines, "\n")
}

// JSONOutput holds the structured JSON output.
type JSONOutput struct {
	Score    int            `json:"score"`
	Rating   string         `json:"rating"`
	Summary  map[string]int `json:"summary"`
	Findings []jsonFinding  `json:"findings"`
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
	return JSONWriterWithScore(w, r, r.Score(), r.Rating(), r.Summary())
}

// JSONWriterWithScore renders JSON using externally provided score values.
func JSONWriterWithScore(w io.Writer, r *scanner.Report, score int, rating scanner.Rating, summary map[scanner.Severity]int) error {
	out := JSONOutput{
		Score:  score,
		Rating: string(rating),
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

func moduleOrder(groups map[string][]scanner.Finding) []string {
	order := []string{"transport", "keys", "channels", "access", "privacy", "hygiene"}
	var result []string
	for _, m := range order {
		if _, ok := groups[m]; ok {
			result = append(result, m)
		}
	}
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
	return strings.ToUpper(mod[:1]) + mod[1:]
}
