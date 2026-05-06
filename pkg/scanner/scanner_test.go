package scanner

import "testing"

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Info, "INFO"},
		{Low, "LOW"},
		{Medium, "MEDIUM"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverity_Points(t *testing.T) {
	tests := []struct {
		sev    Severity
		points int
	}{
		{Info, 0},
		{Low, 2},
		{Medium, 5},
		{High, 10},
		{Critical, 15},
	}
	for _, tt := range tests {
		if got := tt.sev.Points(); got != tt.points {
			t.Errorf("Severity(%d).Points() = %d, want %d", tt.sev, got, tt.points)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
		err   bool
	}{
		{"info", Info, false},
		{"HIGH", High, false},
		{"critical", Critical, false},
		{"CRIT", Critical, false},
		{"med", Medium, false},
		{"banana", Info, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParseSeverity(%q) error = %v, wantErr = %v", tt.input, err, tt.err)
		}
		if !tt.err && got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestReport_Score_Perfect(t *testing.T) {
	r := &Report{}
	if s := r.Score(); s != 100 {
		t.Errorf("empty report score = %d, want 100", s)
	}
}

func TestReport_Score_Deductions(t *testing.T) {
	r := &Report{}
	r.Add(Finding{ID: "T-1", Severity: Critical}) // -15
	r.Add(Finding{ID: "T-2", Severity: High})     // -10
	r.Add(Finding{ID: "T-3", Severity: Medium})   // -5
	r.Add(Finding{ID: "T-4", Severity: Low})      // -2
	r.Add(Finding{ID: "T-5", Severity: Info})     // -0

	want := 100 - 15 - 10 - 5 - 2
	if s := r.Score(); s != want {
		t.Errorf("score = %d, want %d", s, want)
	}
}

func TestReport_Score_Floor(t *testing.T) {
	r := &Report{}
	for i := 0; i < 10; i++ {
		r.Add(Finding{Severity: Critical})
	}
	if s := r.Score(); s != 0 {
		t.Errorf("score = %d, want 0 (floor)", s)
	}
}

func TestReport_Rating(t *testing.T) {
	tests := []struct {
		findings int
		severity Severity
		want     Rating
	}{
		{0, Info, RatingHardened},         // 100
		{1, Medium, RatingHardened},       // 95
		{2, High, RatingAcceptable},       // 80
		{5, High, RatingNeedsWork},        // 50
		{7, Critical, RatingCriticalRisk}, // -5 → 0
	}
	for _, tt := range tests {
		r := &Report{}
		for i := 0; i < tt.findings; i++ {
			r.Add(Finding{Severity: tt.severity})
		}
		if got := r.Rating(); got != tt.want {
			t.Errorf("%d × %s → rating %q, want %q (score=%d)",
				tt.findings, tt.severity, got, tt.want, r.Score())
		}
	}
}

func TestReport_HasFindingsAtOrAbove(t *testing.T) {
	r := &Report{}
	r.Add(Finding{Severity: Medium})
	r.Add(Finding{Severity: Low})

	if r.HasFindingsAtOrAbove(Critical) {
		t.Error("should not have Critical findings")
	}
	if r.HasFindingsAtOrAbove(High) {
		t.Error("should not have High findings")
	}
	if !r.HasFindingsAtOrAbove(Medium) {
		t.Error("should have Medium findings")
	}
	if !r.HasFindingsAtOrAbove(Low) {
		t.Error("should have Low findings")
	}
}

func TestReport_Summary(t *testing.T) {
	r := &Report{}
	r.Add(Finding{Severity: Critical})
	r.Add(Finding{Severity: Critical})
	r.Add(Finding{Severity: High})
	r.Add(Finding{Severity: Info})

	s := r.Summary()
	if s[Critical] != 2 {
		t.Errorf("Critical count = %d, want 2", s[Critical])
	}
	if s[High] != 1 {
		t.Errorf("High count = %d, want 1", s[High])
	}
	if s[Info] != 1 {
		t.Errorf("Info count = %d, want 1", s[Info])
	}
	if s[Medium] != 0 {
		t.Errorf("Medium count = %d, want 0", s[Medium])
	}
}
