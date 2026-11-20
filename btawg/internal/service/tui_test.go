package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kr/pty"
)

func TestTUIQuitsOnQ(t *testing.T) {
	tuiRefreshInterval = time.Hour
	t.Cleanup(func() { tuiRefreshInterval = time.Second })

	var actions []string
	tuiControl = func(u Unit, action string) error { actions = append(actions, action); return nil }
	tuiState = func(u Unit) (string, bool, error) { return "inactive", false, nil }
	t.Cleanup(func() {
		tuiControl = func(u Unit, action string) error { return u.Control(action) }
		tuiState = func(u Unit) (string, bool, error) { return u.State() }
	})

	in := bytes.NewReader([]byte("q"))
	out := &bytes.Buffer{}
	if err := runTUI(in, out, Server, nil, nil); err != nil {
		t.Fatalf("runTUI: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("unexpected actions: %v", actions)
	}
	if !strings.Contains(out.String(), "btawg-server") {
		t.Fatalf("missing header: %s", out.String())
	}
}

func TestTUIServiceActions(t *testing.T) {
	tuiRefreshInterval = time.Hour
	t.Cleanup(func() { tuiRefreshInterval = time.Second })

	actions := make(chan string, 10)
	tuiControl = func(u Unit, action string) error { actions <- action; return nil }
	tuiState = func(u Unit) (string, bool, error) { return "active", true, nil }
	t.Cleanup(func() {
		tuiControl = func(u Unit, action string) error { return u.Control(action) }
		tuiState = func(u Unit) (string, bool, error) { return u.State() }
	})

	in := bytes.NewReader([]byte("stq"))
	out := io.Discard
	if err := runTUI(in, out, Server, nil, nil); err != nil {
		t.Fatalf("runTUI: %v", err)
	}
	close(actions)
	var got []string
	for a := range actions {
		got = append(got, a)
	}
	want := []string{"start", "stop"}
	if len(got) != len(want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("action %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTUIToggleDisableWhenEnabled(t *testing.T) {
	tuiRefreshInterval = time.Hour
	t.Cleanup(func() { tuiRefreshInterval = time.Second })

	actions := make(chan string, 10)
	tuiControl = func(u Unit, action string) error { actions <- action; return nil }
	tuiState = func(u Unit) (string, bool, error) { return "active", true, nil }
	t.Cleanup(func() {
		tuiControl = func(u Unit, action string) error { return u.Control(action) }
		tuiState = func(u Unit) (string, bool, error) { return u.State() }
	})

	in := bytes.NewReader([]byte("bq"))
	out := io.Discard
	if err := runTUI(in, out, Server, nil, nil); err != nil {
		t.Fatalf("runTUI: %v", err)
	}
	close(actions)
	var got []string
	for a := range actions {
		got = append(got, a)
	}
	if len(got) != 1 || got[0] != "disable" {
		t.Fatalf("actions = %v, want [disable]", got)
	}
}

func TestTUIExtraCallback(t *testing.T) {
	tuiRefreshInterval = time.Hour
	t.Cleanup(func() { tuiRefreshInterval = time.Second })

	tuiState = func(u Unit) (string, bool, error) { return "active", true, nil }
	t.Cleanup(func() {
		tuiState = func(u Unit) (string, bool, error) { return u.State() }
	})

	lines := func() ([]string, error) {
		return []string{"1080 mode-a", "1081 mode-b"}, nil
	}
	extra := func(key byte, selected int) (string, error) {
		if key == ' ' {
			return fmt.Sprintf("toggled %d", selected), nil
		}
		return "", errors.New("bad key")
	}

	in := bytes.NewReader([]byte("\x1b[B vq"))
	out := &bytes.Buffer{}
	if err := runTUI(in, out, Client, lines, extra); err != nil {
		t.Fatalf("runTUI: %v", err)
	}
	if !strings.Contains(out.String(), "toggled 1") {
		t.Fatalf("missing toggle message: %s", out.String())
	}
	if !strings.Contains(out.String(), "error: bad key") {
		t.Fatalf("missing error message: %s", out.String())
	}
}

func TestTUIRunsOnPTY(t *testing.T) {
	tuiRefreshInterval = time.Hour
	t.Cleanup(func() { tuiRefreshInterval = time.Second })

	tuiState = func(u Unit) (string, bool, error) { return "active", true, nil }
	t.Cleanup(func() {
		tuiState = func(u Unit) (string, bool, error) { return u.State() }
	})

	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty not available: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	done := make(chan error, 1)
	go func() {
		done <- runTUI(slave, slave, Server, nil, nil)
	}()

	if _, err := master.Write([]byte("q")); err != nil {
		t.Fatalf("write pty: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runTUI on pty: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TUI did not exit on pty")
	}
}

