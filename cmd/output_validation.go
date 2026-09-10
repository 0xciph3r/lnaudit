package cmd

import (
	"fmt"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func validateOutputFlagValues(format string, allowedFormats map[string]struct{}, allowedFormatsLabel, failOnValue, minSeverityValue string) error {
	if _, ok := allowedFormats[format]; !ok {
		return fmt.Errorf("invalid --format %q: supported formats are %s", format, strings.TrimSpace(allowedFormatsLabel))
	}

	if _, err := scanner.ParseSeverity(failOnValue); err != nil {
		return fmt.Errorf("invalid --fail-on value %q: %w", failOnValue, err)
	}

	if _, err := scanner.ParseSeverity(minSeverityValue); err != nil {
		return fmt.Errorf("invalid --min-severity value %q: %w", minSeverityValue, err)
	}

	return nil
}
