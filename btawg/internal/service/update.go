package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Version is set to the release tag by the GitHub build.
var Version = "dev"

const (
	latestRelease = "https://api.github.com/repos/h1w/bittorrent-tunnel/releases/latest"
	assetBase     = "https://github.com/h1w/bittorrent-tunnel/releases/download/"
	maxAssetSize  = 64 << 20
)

type updateResult struct {
	installed, latest string
	updated           bool
}

func releaseSupported() bool {
	return runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
}

func (u Unit) updateScreen() (*Screen, error) {
	if !releaseSupported() {
		return nil, fmt.Errorf("GitHub release binaries are only available for Linux amd64")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := directUpdateClient()
	defer client.CloseIdleConnections()
	result, err := u.updateFrom(ctx, client)
	if err != nil {
		return nil, err
	}
	text := fmt.Sprintf("Installed: %s\nLatest GitHub release: %s\n\nNo update needed.", result.installed, result.latest)
	if result.updated {
		text = fmt.Sprintf("Updated %s → %s.\n\nReopen the TUI to use the new version.", result.installed, result.latest)
	}
	return &Screen{Title: "GitHub update", Text: text}, nil
}

func directUpdateClient() *http.Client {
	return &http.Client{
		// No proxy lookup, including HTTP_PROXY and HTTPS_PROXY. btawg
		// does not install an Internet default route on either host.
		Transport: &http.Transport{ForceAttemptHTTP2: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) < 10 && req.URL.Scheme == "https" && req.URL.User == nil {
				switch req.URL.Host {
				case "github.com", "api.github.com", "release-assets.githubusercontent.com":
					return nil
				}
			}
			return fmt.Errorf("unexpected GitHub release redirect")
		},
	}
}

func (u Unit) updateFrom(ctx context.Context, client *http.Client) (updateResult, error) {
	var result updateResult
	path := u.binaryPath()
	lock, err := os.OpenFile(path+".update.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return result, fmt.Errorf("open update lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return result, fmt.Errorf("lock update: %w", err)
	}
	result, err = u.checkRelease(ctx, client)
	if err != nil || !result.updated {
		return result, err
	}
	return result, u.applyRelease(ctx, client, result.latest)
}

func (u Unit) availableRelease(ctx context.Context, client *http.Client) string {
	if result, err := u.checkRelease(ctx, client); err == nil && result.updated {
		return result.latest
	}
	return ""
}

func (u Unit) checkRelease(ctx context.Context, client *http.Client) (updateResult, error) {
	var result updateResult

	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	out, err := exec.CommandContext(versionCtx, u.binaryPath(), "--version").Output()
	cancel()
	result.installed = strings.TrimSpace(string(out))
	current, valid := stableVersion(result.installed)
	if err != nil || !valid {
		return result, fmt.Errorf("installed binary has no release version; install a current GitHub release manually first")
	}

	metadata, err := getReleaseFile(ctx, client, latestRelease)
	if err != nil {
		return result, fmt.Errorf("check latest release: %w", err)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	err = json.NewDecoder(io.LimitReader(metadata, 1<<20)).Decode(&release)
	metadata.Close()
	if err != nil {
		return result, fmt.Errorf("read release metadata: %w", err)
	}
	result.latest = release.Tag
	latest, valid := stableVersion(result.latest)
	if !valid || release.Draft || release.Prerelease {
		return result, fmt.Errorf("latest GitHub release has no stable version tag")
	}
	for i := range latest {
		if latest[i] != current[i] {
			result.updated = latest[i] > current[i]
			break
		}
	}
	return result, nil
}

func stableVersion(tag string) ([3]uint64, bool) {
	var version [3]uint64
	if !strings.HasPrefix(tag, "v") {
		return version, false
	}
	parts := strings.Split(tag[1:], ".")
	if len(parts) != len(version) {
		return version, false
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil || len(part) > 1 && part[0] == '0' {
			return version, false
		}
		version[i] = n
	}
	return version, true
}

func getReleaseFile(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("GitHub returned %s", res.Status)
	}
	return res.Body, nil
}

func (u Unit) applyRelease(ctx context.Context, client *http.Client, tag string) error {
	base := assetBase + tag + "/"
	name := u.binaryName()
	want, err := releaseChecksum(ctx, client, base, name)
	if err != nil {
		return fmt.Errorf("get release checksum: %w", err)
	}

	path := u.binaryPath()
	dir, err := os.MkdirTemp(filepath.Dir(path), ".btawg-update-")
	if err != nil {
		return fmt.Errorf("stage update: %w", err)
	}
	keepBackup := false
	defer func() {
		if !keepBackup {
			os.RemoveAll(dir)
		}
	}()
	staged := filepath.Join(dir, name)
	if err := downloadBinary(ctx, client, base+name, staged, want); err != nil {
		return fmt.Errorf("download %s %s: %w", name, tag, err)
	}
	backup := filepath.Join(dir, "previous")
	if err := os.Link(path, backup); err != nil {
		return fmt.Errorf("back up installed binary: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("replace installed binary: %w", err)
	}
	if err := unitAction(u.unitName(), "try-restart"); err != nil {
		if restoreErr := os.Rename(backup, path); restoreErr != nil {
			keepBackup = true
			return errors.Join(err, fmt.Errorf("restore previous binary (backup at %s): %w", backup, restoreErr))
		}
		if restartErr := u.Control("restart"); restartErr != nil {
			return errors.Join(err, fmt.Errorf("previous binary restored, but service restart failed: %w", restartErr))
		}
		return fmt.Errorf("previous version restored after restart failed: %w", err)
	}
	return nil
}

func releaseChecksum(ctx context.Context, client *http.Client, base, name string) ([]byte, error) {
	body, err := getReleaseFile(ctx, client, base+"SHA256SUMS")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	scanner := bufio.NewScanner(io.LimitReader(body, 64<<10))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			file := strings.TrimPrefix(fields[1], "*")
			if file == name || file == "dist/"+name {
				digest, err := hex.DecodeString(fields[0])
				if err != nil || len(digest) != sha256.Size {
					return nil, fmt.Errorf("invalid SHA-256 for %s", name)
				}
				return digest, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no SHA-256 for %s", name)
}

func downloadBinary(ctx context.Context, client *http.Client, url, path string, want []byte) error {
	body, err := getReleaseFile(ctx, client, url)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(body, maxAssetSize+1))
	if err != nil {
		return err
	}
	if n == 0 || n > maxAssetSize || !bytes.Equal(hash.Sum(nil), want) {
		return fmt.Errorf("invalid binary size or SHA-256 mismatch")
	}
	return f.Sync()
}
