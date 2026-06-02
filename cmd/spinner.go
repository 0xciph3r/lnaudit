package cmd

import (
	"fmt"
	"strings"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00D9FF"))
	phaseStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B97AA"))
	titleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F7FAFC")).Bold(true)
	doneStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981"))
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444"))
)

// scanResult holds the outcome of the scan execution.
type scanResult struct {
	report   *scanner.Report
	warnings []string
	err      error
}

// phaseMsg updates the spinner's status text.
type phaseMsg string

// scanDoneMsg signals scan completion.
type scanDoneMsg struct {
	result scanResult
}

// scanModel is the Bubble Tea model for the scanning UI.
type scanModel struct {
	spinner    spinner.Model
	phase      string
	phases     []string
	result     *scanResult
	quitting   bool
	scanFn     func(prog *tea.Program) scanResult
	programRef *tea.Program
}

func newScanModel(scanFn func(prog *tea.Program) scanResult) scanModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle

	return scanModel{
		spinner: s,
		phase:   "Initializing...",
		scanFn:  scanFn,
	}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.startScan(),
	)
}

func (m scanModel) startScan() tea.Cmd {
	return func() tea.Msg {
		result := m.scanFn(m.programRef)
		return scanDoneMsg{result: result}
	}
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}

	case phaseMsg:
		m.phase = string(msg)
		m.phases = append(m.phases, string(msg))
		return m, nil

	case scanDoneMsg:
		m.result = &msg.result
		m.quitting = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m scanModel) View() string {
	if m.quitting {
		return m.finalView()
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  lnaudit"))
	b.WriteString(phaseStyle.Render(" — security scanner\n\n"))

	// Show completed phases
	for _, p := range m.phases {
		if p != m.phase {
			fmt.Fprintf(&b, "  %s %s\n",
				doneStyle.Render("✓"),
				phaseStyle.Render(p),
			)
		}
	}

	// Current phase with spinner
	fmt.Fprintf(&b, "  %s %s\n",
		m.spinner.View(),
		m.phase,
	)

	b.WriteString("\n")

	return b.String()
}

func (m scanModel) finalView() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  lnaudit"))
	b.WriteString(phaseStyle.Render(" — security scanner\n\n"))

	for _, p := range m.phases {
		fmt.Fprintf(&b, "  %s %s\n",
			doneStyle.Render("✓"),
			phaseStyle.Render(p),
		)
	}

	if m.result != nil && m.result.err != nil {
		fmt.Fprintf(&b, "\n  %s %s\n",
			errStyle.Render("✗"),
			errStyle.Render(m.result.err.Error()),
		)
	} else {
		fmt.Fprintf(&b, "\n  %s\n",
			doneStyle.Render("  Scan complete."),
		)
	}

	b.WriteString("\n")

	return b.String()
}

// sendPhase sends a phase update to the Bubble Tea program.
func sendPhase(p *tea.Program, phase string) {
	if p != nil {
		p.Send(phaseMsg(phase))
	}
}
