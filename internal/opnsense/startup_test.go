package opnsense

import (
	"context"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
)

func TestStartup_RepairsUnservedManagedRow(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "served", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.Reconfigure()
	f.AddRow(fake.Row{Hostname: "unserved", Domain: "example.com", RR: "A", Server: "192.0.2.2", Description: "external-dns"})
	p := testProvider(t, f)
	p.Startup(context.Background())
	if f.Reconfigures() != 2 || len(f.Served()) != 2 {
		t.Errorf("reconfigures=%d served=%d; want one repair reconfigure", f.Reconfigures(), len(f.Served()))
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Errorf("Ready: %v", err)
	}
}

func TestStartup_NoRepairWhenConsistent(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "a", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.AddRow(fake.Row{Hostname: "hand", Domain: "example.com", RR: "A", Server: "192.0.2.3", Description: "device"})
	f.Reconfigure()
	p := testProvider(t, f)
	p.Startup(context.Background())
	if f.Reconfigures() != 1 {
		t.Errorf("reconfigures = %d, want no repair", f.Reconfigures())
	}
}

func TestStartup_FailureLeavesNotReady(t *testing.T) {
	f := fake.New(t)
	f.Inject(fake.Fault{Op: fake.OpStatus, Status: 500, Times: 100})
	f.Inject(fake.Fault{Op: fake.OpSearch, Status: 500, Times: 100})
	p := testProvider(t, f)
	p.cfg.RetryAttempts = 1
	done := make(chan struct{})
	go func() { p.Startup(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Startup did not return")
	}
	if err := p.Ready(context.Background()); err == nil {
		t.Error("Ready should fail while search returns 500")
	}
}
