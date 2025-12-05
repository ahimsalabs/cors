package cors_test

import (
	"strings"
	"testing"

	"github.com/ahimsalabs/cors"
)

// TestOrigin_Format validates origin string format per RFC 6454 §4.
// Origins must be scheme "://" host [":" port] with no path, query, or fragment.
func TestOrigin_Format(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantError bool
	}{
		// Scheme required (RFC 6454 §4)
		{"no scheme", "example.com", true},
		{"no scheme separator", "httpsexample.com", true},
		{"single slash", "https:/example.com", true},
		{"backslash", "https:\\\\example.com", true},

		// Non-http(s) schemes rejected
		{"javascript scheme", "javascript:alert(1)", true},
		{"data scheme", "data:text/html,<h1>x</h1>", true},
		{"file scheme", "file:///etc/passwd", true},

		// No path/query/fragment (RFC 6454 §6.1 - origin is scheme+host+port only)
		{"with path", "https://example.com/api", true},
		{"with query", "https://example.com?foo=bar", true},
		{"with fragment", "https://example.com#section", true},

		// Userinfo not allowed in origins
		{"with userinfo", "https://user:pass@example.com", true},

		// Whitespace rejected
		{"leading space", " https://example.com", true},
		{"trailing space", "https://example.com ", true},
		{"internal space", "https://exam ple.com", true},
		{"tab", "https://exam\tple.com", true},

		// Valid origins
		{"https", "https://example.com", false},
		{"http", "http://example.com", false},
		{"with port", "https://example.com:8443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cors.Origins(tt.origin).Handler()
			if tt.wantError && err == nil {
				t.Errorf("expected error for origin %q", tt.origin)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error for origin %q: %v", tt.origin, err)
			}
		})
	}
}

// TestOrigin_DefaultPortElision validates RFC 6454 §6.1 requirement that
// default ports (80 for http, 443 for https) must be omitted from origin strings.
func TestOrigin_DefaultPortElision(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantError bool
	}{
		{"http:80 must be elided", "http://example.com:80", true},
		{"https:443 must be elided", "https://example.com:443", true},
		{"http without port", "http://example.com", false},
		{"https without port", "https://example.com", false},
		{"http non-default port", "http://example.com:8080", false},
		{"https non-default port", "https://example.com:8443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cors.Origins(tt.origin).Handler()
			if tt.wantError && err == nil {
				t.Error("expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestOrigin_PortRange validates port numbers are in valid TCP range 1-65535.
func TestOrigin_PortRange(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantError bool
	}{
		{"port 0", "http://example.com:0", true},
		{"port 65536", "http://example.com:65536", true},
		{"port non-numeric", "http://example.com:abc", true},
		{"port 1", "http://example.com:1", false},
		{"port 65535", "http://example.com:65535", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cors.Origins(tt.origin).Handler()
			if tt.wantError && err == nil {
				t.Error("expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestOrigin_NullRejected validates that the literal string "null" is rejected.
// Per RFC 6454 §7, "null" is used for privacy-sensitive contexts and is trivially
// spoofable (sandboxed iframes, data: URIs, file: origins all serialize to "null").
func TestOrigin_NullRejected(t *testing.T) {
	_, err := cors.Origins("null").Handler()
	if err == nil {
		t.Error("expected error for null origin")
	}
	if err != nil && !strings.Contains(err.Error(), "null") {
		t.Errorf("error should mention null: %v", err)
	}
}

// TestCredentials_RequireSecureTransport validates that AllowCredentials()
// requires https:// (or localhost for development). This prevents credentials
// from being sent over unencrypted connections to remote hosts.
func TestCredentials_RequireSecureTransport(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantError bool
	}{
		// http:// to remote hosts rejected with credentials
		{"http remote", "http://example.com", true},
		{"http remote with port", "http://example.com:8080", true},
		{"http private IP", "http://192.168.1.1:8080", true},
		{"http 0.0.0.0", "http://0.0.0.0:8080", true},

		// localhost exceptions for development
		{"http localhost", "http://localhost:3000", false},
		{"http 127.0.0.1", "http://127.0.0.1:8080", false},
		{"http [::1]", "http://[::1]:8080", false},

		// https:// always allowed
		{"https", "https://example.com", false},
		{"https with port", "https://example.com:8443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cors.Origins(tt.origin).AllowCredentials().Handler()
			if tt.wantError && err == nil {
				t.Errorf("expected error for %q with credentials", tt.origin)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestOriginSuffix_RejectsPublicSuffixes validates that OriginSuffix() rejects
// patterns that match public suffixes (eTLDs) from the Public Suffix List.
// These are domains where anyone can register subdomains, making suffix matching dangerous.
func TestOriginSuffix_RejectsPublicSuffixes(t *testing.T) {
	// Public suffixes - anyone can register subdomains
	publicSuffixes := []string{
		"com", "io", "co.uk",
		"github.io",      // GitHub Pages
		"herokuapp.com",  // Heroku
		"vercel.app",     // Vercel
		"netlify.app",    // Netlify
		"pages.dev",      // Cloudflare Pages
		"workers.dev",    // Cloudflare Workers
		"azurewebsites.net",
		"firebaseapp.com",
		"appspot.com",
		"ngrok.io",
		"s3.amazonaws.com",
		"cloudfront.net",
	}

	for _, suffix := range publicSuffixes {
		t.Run(suffix, func(t *testing.T) {
			_, err := cors.OriginSuffix(suffix).Handler()
			if err == nil {
				t.Errorf("should reject public suffix %q", suffix)
			}
		})
	}

	// Specific subdomains of public suffixes should be allowed
	allowedDomains := []string{
		"example.com",
		"myapp.github.io",
		"myapp.herokuapp.com",
		"api.example.com",
	}

	for _, domain := range allowedDomains {
		t.Run("allowed_"+domain, func(t *testing.T) {
			_, err := cors.OriginSuffix(domain).Handler()
			if err != nil {
				t.Errorf("should allow %q: %v", domain, err)
			}
		})
	}
}

// TestOrigin_MustBeLowercase validates that uppercase origins are rejected.
// Browsers normalize origins to lowercase, so uppercase would never match.
func TestOrigin_MustBeLowercase(t *testing.T) {
	tests := []struct {
		origin    string
		wantError bool
	}{
		{"https://EXAMPLE.COM", true},
		{"https://Example.com", true},
		{"HTTPS://example.com", true},
		{"https://example.COM", true},
		{"https://example.com", false},
		{"http://localhost:3000", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			_, err := cors.Origins(tt.origin).Handler()
			if tt.wantError && err == nil {
				t.Errorf("expected error for %q", tt.origin)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestMustHandler_Panics validates that MustHandler() panics on invalid configuration.
func TestMustHandler_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()

	cors.Origins("http://example.com").AllowCredentials().MustHandler()
}
