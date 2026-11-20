package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// tuiControl and tuiState are overridable in tests.
var (
	tuiControl         = func(u Unit, action string) error { return u.Control(action) }
	tuiState           = func(u Unit) (string, bool, error) { return u.State() }
	tuiRefreshInterval = time.Second
)

// TUI runs an interactive terminal UI for the given unit. The client callback
// supplies optional content lines (e.g. client proxy modes); the extra callback
// receives any key that is not handled by the built-in service actions.
// Built-in keys: arrows navigate, s=start, t=stop, r=restart, b=toggle enable,
// q or Ctrl-C=quit.
func TUI(unit Unit, client func() ([]string, error), extra func(key byte, selected int) (message string, err error)) error {
	return runTUI(os.Stdin, os.Stdout, unit, client, extra)
}

func runTUI(in io.Reader, out io.Writer, unit Unit, client func() ([]string, error), extra func(key byte, selected int) (string, error)) error {
	fd, isTerm := in.(*os.File)
	if isTerm {
		old, err := term.MakeRaw(int(fd.Fd()))
		if err != nil {
			isTerm = false
		} else {
			defer term.Restore(int(fd.Fd()), old)
		}
	}

	var (
		mu       sync.Mutex
		selected int
		message  string
		lines    []string
	)
	refreshLines := func() {
		if client == nil {
			lines = nil
			return
		}
		l, err := client()
		if err != nil {
			l = []string{fmt.Sprintf("error: %v", err)}
		}
		lines = l
	}

	draw := func() {
		state, enabled, _ := tuiState(unit)
		if state == "" {
			state = "unknown"
		}
		status := state
		if enabled {
			status += " / enabled"
		} else {
			status += " / disabled"
		}

		var b strings.Builder
		if isTerm {
			b.WriteString("\033[H\033[2J")
		}
		fmt.Fprintf(&b, "btawg-%s  %s\n", unit, status)
		if message != "" {
			fmt.Fprintf(&b, "%s\n", message)
		}
		refreshLines()
		for i, line := range lines {
			if i == selected {
				fmt.Fprintf(&b, "> %s\n", line)
			} else {
				fmt.Fprintf(&b, "  %s\n", line)
			}
		}
		if extra != nil {
			fmt.Fprintln(&b, "Space:toggle  v:show SOCKS5 login  g:regenerate")
		}
		fmt.Fprintln(&b, "s:start t:stop r:restart b:autostart q:quit")
		out.Write([]byte(b.String()))
	}

	draw()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	// Stop the refresh goroutine before returning so it cannot read the UI
	// hooks after the caller regains control (LIFO: cancel runs before Wait).
	defer wg.Wait()
	defer cancel()

	// Refresh state periodically so the UI shows live systemd status.
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(tuiRefreshInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				mu.Lock()
				draw()
				mu.Unlock()
			}
		}
	}()

	r := bufio.NewReader(in)
	for {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}
		mu.Lock()
		switch c {
		case 3: // Ctrl-C
			mu.Unlock()
			return nil
		case 'q':
			mu.Unlock()
			return nil
		case 's':
			message = ""
			if err := tuiControl(unit, "start"); err != nil {
				message = fmt.Sprintf("error: %v", err)
			}
		case 't':
			message = ""
			if err := tuiControl(unit, "stop"); err != nil {
				message = fmt.Sprintf("error: %v", err)
			}
		case 'r':
			message = ""
			if err := tuiControl(unit, "restart"); err != nil {
				message = fmt.Sprintf("error: %v", err)
			}
		case 'b':
			message = ""
			_, enabled, _ := tuiState(unit)
			if enabled {
				message = "disabling autostart..."
				if err := tuiControl(unit, "disable"); err != nil {
					message = fmt.Sprintf("error: %v", err)
				}
			} else {
				message = "enabling autostart..."
				if err := tuiControl(unit, "enable"); err != nil {
					message = fmt.Sprintf("error: %v", err)
				}
			}
		case 27: // ESC sequences (arrows)
			next, err := r.Peek(2)
			if err == nil && next[0] == '[' {
				r.Discard(2)
				switch next[1] {
				case 'A': // up
					if selected > 0 {
						selected--
					}
				case 'B': // down
					if selected < len(lines)-1 {
						selected++
					}
				}
			}
		default:
			if extra != nil {
				msg, err := extra(c, selected)
				if err != nil {
					message = fmt.Sprintf("error: %v", err)
				} else {
					message = msg
				}
			}
		}
		draw()
		mu.Unlock()
	}
}
