// Package emailguard provides fast, practical heuristics for validating
// business email domains during user signup.
//
// It filters out disposable, masked, or misconfigured email domains
// by combining lightweight DNS inspection (MX lookups) with a curated
// blocklist of known temporary email providers.
//
// Key behaviors:
//   - Auto-clones and updates the public disposable-email-domains list
//   - Checks for valid MX records with a short timeout
//   - Caches DNS and verdict results for low latency
//   - Rejects domains or MX hosts matching disposable or masking patterns
//   - Allows configurable consumer-domain allowlist (e.g. Gmail, Outlook)
//
// This package is optimized for B2B SaaS signup flows where
// verifying the authenticity of an email domain matters more
// than tolerating edge cases in personal mail services.
//
// Example usage:
//
//	import "yourproject/emailguard"
//
//	ok := emailguard.IsLegitEmail("user@company.com")
//	if !ok {
//	    fmt.Println("reject: unverified or disposable domain")
//	}
package emailguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"golang.org/x/net/publicsuffix"
)

const (
	repoURL       = "https://github.com/disposable-email-domains/disposable-email-domains.git"
	repoDir       = "/tmp/disposable-email-domains"
	blocklistFile = "disposable_email_blocklist.conf"

	mxTimeout    = 1 * time.Second  // keep snappy
	cacheTTL     = 5 * time.Minute  // domain/mx caches
	pullCooldown = 30 * time.Minute // blocklist repo refresh
)

// --- policy knobs ---

var allowlist = map[string]struct{}{
	"gmail.com":      {},
	"googlemail.com": {},
	"outlook.com":    {},
	"hotmail.com":    {},
	"live.com":       {},
	"yahoo.com":      {},
	"icloud.com":     {},
	"proton.me":      {},
	"protonmail.com": {},
	"fastmail.com":   {},
}

// MX hostname keywords that strongly indicate masking/forwarding/temp
var mxBadKeywords = []string{
	"mask",
	"alias",
	"relay",
	"forward",
	"tempmail",
	"mailinator",
	"disposable",
	"burner",
}

// --- disposable set + once ---

var (
	tempMails       map[string]struct{}
	blocklistLoaded bool
	loadOnce        sync.Once
)

// --- caches (simple TTL maps) ---

type verdictEntry struct {
	val bool
	exp time.Time
}
type mxEntry struct {
	hosts []string
	exp   time.Time
}

var (
	verdictCache = make(map[string]verdictEntry) // key: domain
	mxCache      = make(map[string]mxEntry)      // key: domain
	cacheMu      sync.RWMutex
)

func init() {
	// lazy + safe: if this fails, we still run with empty set
	LoadTempMails()
}

// IsLegitEmail returns true only if the domain looks like a legit mailbox domain
// (no MX => reject, disposable => reject, masking MX => reject).
func IsLegitEmail(email string) bool {
	email = strings.TrimSpace(email)
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	domain := normDomain(email[at+1:])
	if domain == "" {
		return false
	}

	// verdict cache hit
	if ok, hit := getVerdictCached(domain); hit {
		return ok
	}

	// 1) allow common consumer providers you explicitly permit
	if inSet(allowlist, domain) {
		setVerdictCached(domain, true)
		return true
	}

	// ensure blocklist is loaded (no-op after first call)
	LoadTempMails()

	// 2) block if email domain or its eTLD+1 is disposable
	if inSet(tempMails, domain) {
		setVerdictCached(domain, false)
		return false
	}
	if rd, err := registrableDomain(domain); err == nil && inSet(tempMails, rd) {
		setVerdictCached(domain, false)
		return false
	}

	// 3) require MX records (cached, 1s timeout)
	mxHosts := checkForMXCached(domain)
	if len(mxHosts) == 0 {
		setVerdictCached(domain, false)
		return false
	}

	// 4) MX intelligence
	for _, h := range mxHosts {
		lh := normDomain(h)
		// 4a) keyword scan
		for _, kw := range mxBadKeywords {
			if strings.Contains(lh, kw) {
				setVerdictCached(domain, false)
				return false
			}
		}
		// 4b) disposable check on MX registrable domain
		if rd, err := registrableDomain(lh); err == nil && inSet(tempMails, rd) {
			setVerdictCached(domain, false)
			return false
		}
	}

	setVerdictCached(domain, true)
	return true
}

// --- MX lookup with tiny TTL cache ---

func checkForMXCached(domain string) []string {
	cacheMu.RLock()
	if e, ok := mxCache[domain]; ok && time.Now().Before(e.exp) {
		hostsCopy := append([]string(nil), e.hosts...)
		cacheMu.RUnlock()
		return hostsCopy
	}
	cacheMu.RUnlock()

	hosts := checkForMX(domain)

	cacheMu.Lock()
	mxCache[domain] = mxEntry{hosts: append([]string(nil), hosts...), exp: time.Now().Add(cacheTTL)}
	cacheMu.Unlock()

	return hosts
}

// Checks for MX of an email domain. Returns list of MX hostnames.
func checkForMX(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), mxTimeout)
	defer cancel()

	// use DefaultResolver with context; this respects our timeout
	recs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(recs) == 0 {
		return nil
	}
	out := make([]string, 0, len(recs))
	for _, mx := range recs {
		if mx == nil || mx.Host == "" {
			continue
		}
		out = append(out, strings.TrimSpace(mx.Host))
	}
	return out
}

// --- disposable list ---

// LoadTempMails clones or pulls the disposable list and returns a set of domains.
// Safe to call multiple times; work is done once per process.
func LoadTempMails() map[string]struct{} {
	loadOnce.Do(func() {
		if err := ensureRepo(repoURL, repoDir, "", ""); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: cannot prepare blocklist repo: %v\n", err)
			tempMails = make(map[string]struct{}, 0)
			blocklistLoaded = true
			return
		}

		fp := filepath.Join(repoDir, blocklistFile)
		f, err := os.Open(fp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: cannot open blocklist %s: %v\n", fp, err)
			tempMails = make(map[string]struct{}, 0)
			blocklistLoaded = true
			return
		}
		defer f.Close()

		set := make(map[string]struct{}, 40000)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			set[normDomain(line)] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: scanning blocklist: %v\n", err)
		}
		tempMails = set
		blocklistLoaded = true
	})
	return tempMails
}

// --- git helpers ---

// ensureRepo clones or pulls the repo into repoDir. Optional basic auth can be provided.
func ensureRepo(url, dir, username, password string) error {
	// if dir doesn't exist -> clone
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		// clone fresh
		os.RemoveAll(dir)
		_, err := git.PlainClone(dir, false, &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
			Auth:     basicAuthOrNil(username, password),
			Depth:    1,
		})
		return err
	}

	// else open and pull (but not more often than pullCooldown)
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	stamp := filepath.Join(dir, ".lastpull")
	if fresh(stamp, pullCooldown) {
		return nil
	}

	pullErr := wt.Pull(&git.PullOptions{
		RemoteName: "origin",
		Depth:      1,
		Auth:       basicAuthOrNil(username, password),
		Force:      true,
	})
	if pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		_ = os.RemoveAll(dir)
		_, cloneErr := git.PlainClone(dir, false, &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
			Auth:     basicAuthOrNil(username, password),
			Depth:    1,
		})
		if cloneErr != nil {
			return fmt.Errorf("pull failed: %v; reclone failed: %w", pullErr, cloneErr)
		}
	}

	_ = os.WriteFile(stamp, []byte(time.Now().Format(time.RFC3339Nano)), 0o644)
	return nil
}

func basicAuthOrNil(user, pass string) *http.BasicAuth {
	if user == "" && pass == "" {
		return nil
	}
	return &http.BasicAuth{Username: user, Password: pass}
}

func fresh(stampPath string, maxAge time.Duration) bool {
	fi, err := os.Stat(stampPath)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < maxAge
}

// registrableDomain returns eTLD+1 (e.g., mx1.mail.tempmail.com.tr -> tempmail.com.tr)
func registrableDomain(host string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(normDomain(host))
}

// --- tiny utils ---

func inSet(m map[string]struct{}, k string) bool {
	_, ok := m[normDomain(k)]
	return ok
}

func normDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func getVerdictCached(domain string) (bool, bool) {
	now := time.Now()
	cacheMu.RLock()
	e, ok := verdictCache[domain]
	cacheMu.RUnlock()
	if !ok || now.After(e.exp) {
		return false, false
	}
	return e.val, true
}

func setVerdictCached(domain string, v bool) {
	cacheMu.Lock()
	verdictCache[domain] = verdictEntry{val: v, exp: time.Now().Add(cacheTTL)}
	cacheMu.Unlock()
}
