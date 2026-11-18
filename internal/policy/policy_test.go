package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
)

func sampleFile() *File {
	return &File{
		Version:  1,
		Defaults: Defaults{TTL: Dur(2 * time.Hour), TTLCeiling: Dur(4 * time.Hour), ProbeTimeout: Dur(5 * time.Second)},
		Tools: []Tool{
			{Name: "send_email", Integrity: ChallengeIfTainted, Confidentiality: ChallengeIfHigh, Approvers: []string{"U1"}},
			{Name: "read_file", Integrity: TrustAny, Confidentiality: SensitivityAny, Emits: "file-read", EmitPathArg: "path"},
			{Name: "bash", Integrity: RequireTrusted, Confidentiality: RequireNormal},
		},
		Tasks: []TaskClass{{
			Class: "deploy", TTL: Dur(4 * time.Hour),
			Caps: []CapDecl{
				{Tool: "bash", Pattern: "make*", Sensitivity: labels.SensNormal},
				{Tool: "send_email", Pattern: "*", Sensitivity: labels.SensHigh},
			},
		}},
	}
}

func TestCompileValid(t *testing.T) {
	p, err := Compile(sampleFile())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p.Defaults.TTL.D() != 2*time.Hour {
		t.Errorf("ttl default lost")
	}
	if len(p.Registry.PathRules) != 0 {
		t.Errorf("unexpected path rules")
	}
	tl := p.ToolFor("send_email")
	if tl.Integrity != ChallengeIfTainted || tl.Confidentiality != ChallengeIfHigh {
		t.Errorf("tool verbs lost")
	}
	// undeclared tool gets strict defaults + no cap-gap (deny-by-default posture)
	ul := p.ToolFor("mystery_tool")
	if ul.CapGapChallenge {
		t.Errorf("undeclared tools must not opt into cap-gap challenge")
	}
}

func TestCompileRejectsBadVerbs(t *testing.T) {
	f := sampleFile()
	f.Tools[0].Integrity = "yolo"
	if _, err := Compile(f); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("bad integrity verb must be rejected, got %v", err)
	}
	f = sampleFile()
	f.Tools[1].Confidentiality = "ship-it"
	if _, err := Compile(f); err == nil || !strings.Contains(err.Error(), "confidentiality") {
		t.Fatalf("bad confidentiality verb must be rejected, got %v", err)
	}
	f = sampleFile()
	f.Version = 7
	if _, err := Compile(f); err == nil {
		t.Fatalf("bad version must be rejected")
	}
	f = sampleFile()
	f.Tasks[0].Class = ""
	if _, err := Compile(f); err == nil {
		t.Fatalf("empty task class must be rejected")
	}
}

func TestTTLClampToCeiling(t *testing.T) {
	f := sampleFile()
	f.Tasks[0].TTL = Dur(100 * time.Hour) // above the ceiling
	p, err := Compile(f)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := p.Tasks["deploy"].TTL.D(); got != 4*time.Hour {
		t.Errorf("task ttl must clamp to ceiling, got %s", got)
	}
}

func TestNarrowCapsOnlyNarrows(t *testing.T) {
	p, _ := Compile(sampleFile())
	// empty request: the whole class grant
	all, err := p.NarrowCaps("deploy", nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("narrow(nil) = %d caps, %v", len(all), err)
	}
	// subset request
	sub, err := p.NarrowCaps("deploy", []string{"send_email|*"})
	if err != nil || len(sub) != 1 || sub[0].Tool != "send_email" {
		t.Fatalf("narrow subset failed: %v %v", sub, err)
	}
	// widening attempt: a cap the class does not grant
	if _, err := p.NarrowCaps("deploy", []string{"bash|rm -rf /"}); err == nil {
		t.Fatalf("manifest widening must be refused")
	}
	if _, err := p.NarrowCaps("nope", nil); err == nil {
		t.Fatalf("unknown class must be refused")
	}
}

func TestDiff(t *testing.T) {
	a, _ := Compile(sampleFile())
	bf := sampleFile()
	bf.Tools[0].Integrity = RequireTrusted
	bf.Tasks[0].Caps = append(bf.Tasks[0].Caps, CapDecl{Tool: "read_file", Pattern: "/tmp/**"})
	b, _ := Compile(bf)
	d := Diff(a, b)
	if !strings.Contains(d, "integrity challenge-if-tainted -> require-trusted") {
		t.Errorf("diff must report the verb change; got:\n%s", d)
	}
	if !strings.Contains(d, "caps changed (2 -> 3)") {
		t.Errorf("diff must report the cap addition; got:\n%s", d)
	}
	// identical policies → no changes
	if d := Diff(a, a); d != "no semantic changes" {
		t.Errorf("identical policies must diff clean; got %q", d)
	}
}

func TestPathRulesApplied(t *testing.T) {
	f := sampleFile()
	f.Paths = []PathRuleYAML{
		{Pattern: "/home/op/.secrets/**", Trust: labels.TrustUntrusted, Sensitivity: labels.SensHigh},
	}
	p, err := Compile(f)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	trust, sens := p.Registry.ForPath("/home/op/.secrets/prod.key")
	if trust != labels.TrustUntrusted || sens != labels.SensHigh {
		t.Errorf("path rule not applied: %s/%s", trust, sens)
	}
}
