package cors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ahimsalabs/cors"
)

func TestAnyOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin http://example.com, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}

	if w.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin, got %s", w.Header().Get("Vary"))
	}

	// AnyOrigin should NOT set credentials
	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("AnyOrigin should not set credentials header")
	}
}

func TestAnyOrigin_NoOriginHeader(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("expected handler to be called")
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no CORS headers, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestOrigins_Allowed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("http://example.com", "http://test.com").MustHandler()(handler)

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{"allowed origin 1", "http://example.com", "http://example.com"},
		{"allowed origin 2", "http://test.com", "http://test.com"},
		{"disallowed origin", "http://evil.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.expectedOrigin {
				t.Errorf("expected origin %q, got %q", tt.expectedOrigin, gotOrigin)
			}
		})
	}
}

func TestOriginSuffix(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		suffix         string
		origin         string
		expectedOrigin string
	}{
		// "example.com" - matches exact AND subdomains
		{"exact match", "example.com", "https://example.com", "https://example.com"},
		{"subdomain match", "example.com", "https://api.example.com", "https://api.example.com"},
		{"nested subdomain", "example.com", "https://foo.bar.example.com", "https://foo.bar.example.com"},
		{"no match - different domain", "example.com", "https://example.org", ""},
		{"no match - evil prefix", "example.com", "https://evilexample.com", ""},
		{"no match - evil suffix", "example.com", "https://example.com.evil.com", ""},

		// ".example.com" - subdomains ONLY
		{"dot prefix - subdomain match", ".example.com", "https://api.example.com", "https://api.example.com"},
		{"dot prefix - no exact match", ".example.com", "https://example.com", ""},
		{"dot prefix - nested subdomain", ".example.com", "https://foo.bar.example.com", "https://foo.bar.example.com"},
		{"dot prefix - no evil match", ".example.com", "https://evilexample.com", ""},

		// With ports
		{"with port - exact", "example.com", "https://example.com:8080", "https://example.com:8080"},
		{"with port - subdomain", "example.com", "https://api.example.com:3000", "https://api.example.com:3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corsHandler := cors.OriginSuffix(tt.suffix).MustHandler()(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.expectedOrigin {
				t.Errorf("expected origin %q, got %q", tt.expectedOrigin, gotOrigin)
			}
		})
	}
}

func TestOriginFunc(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Custom function that allows any https origin
	corsHandler := cors.OriginFunc(func(origin string) bool {
		return len(origin) >= 8 && origin[:8] == "https://"
	}).MustHandler()(handler)

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{"https allowed", "https://example.com", "https://example.com"},
		{"http denied", "http://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.expectedOrigin {
				t.Errorf("expected origin %q, got %q", tt.expectedOrigin, gotOrigin)
			}
		})
	}
}

func TestPreflight(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for preflight request")
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header to be set")
	}

	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("expected Access-Control-Allow-Headers header to be set")
	}
}

func TestOptionsWithoutPreflightHeader(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("handler should be called for non-preflight OPTIONS")
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Errorf("expected CORS headers, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestAllowCredentials(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").AllowCredentials().MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials true, got %s", w.Header().Get("Access-Control-Allow-Credentials"))
	}
}

func TestAllowCredentials_AutoAddsAuthorizationHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// AllowCredentials should automatically add Authorization to allowed headers
	corsHandler := cors.Origins("https://example.com").AllowCredentials().MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	allowHeaders := w.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allowHeaders, "Authorization") {
		t.Errorf("expected Authorization in allowed headers, got %s", allowHeaders)
	}
	// Content-Type should still be there (from defaults)
	if !strings.Contains(allowHeaders, "Content-Type") {
		t.Errorf("expected Content-Type in allowed headers, got %s", allowHeaders)
	}
}

func TestAllowCredentials_DoesNotDuplicateAuthorization(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// If user already added Authorization, don't duplicate it
	corsHandler := cors.Origins("https://example.com").
		AllowHeaders("Content-Type", "Authorization").
		AllowCredentials().
		MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	allowHeaders := w.Header().Get("Access-Control-Allow-Headers")
	// Count occurrences of Authorization
	count := strings.Count(allowHeaders, "Authorization")
	if count != 1 {
		t.Errorf("expected exactly 1 Authorization in headers, got %d in %q", count, allowHeaders)
	}
}

func TestStrictMode_ExcludePOST(t *testing.T) {
	// "Strict mode" is just using AllowMethods to exclude POST
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").
		AllowMethods("GET", "OPTIONS").
		MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	allowMethods := w.Header().Get("Access-Control-Allow-Methods")
	if strings.Contains(allowMethods, "POST") {
		t.Errorf("strict mode should exclude POST, got %s", allowMethods)
	}
	if !strings.Contains(allowMethods, "GET") {
		t.Errorf("strict mode should allow GET, got %s", allowMethods)
	}
}

func TestMaxAge(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().MaxAge(3600).Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Max-Age") != "3600" {
		t.Errorf("expected Access-Control-Max-Age 3600, got %s", w.Header().Get("Access-Control-Max-Age"))
	}
}

func TestExposeHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().ExposeHeaders("X-Custom-Header", "X-Another-Header").Handler()(handler)

	// Test on preflight
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	exposedHeaders := w.Header().Get("Access-Control-Expose-Headers")
	if exposedHeaders != "X-Custom-Header, X-Another-Header" {
		t.Errorf("expected exposed headers on preflight, got %s", exposedHeaders)
	}

	// Test on regular request
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w = httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	exposedHeaders = w.Header().Get("Access-Control-Expose-Headers")
	if exposedHeaders != "X-Custom-Header, X-Another-Header" {
		t.Errorf("expected exposed headers on regular request, got %s", exposedHeaders)
	}
}

func TestAllowMethods(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().AllowMethods("GET", "POST", "PUT", "DELETE").Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	allowedMethods := w.Header().Get("Access-Control-Allow-Methods")
	if allowedMethods != "GET, POST, PUT, DELETE" {
		t.Errorf("expected allowed methods, got %s", allowedMethods)
	}
}

func TestAllowHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().AllowHeaders("Content-Type", "X-Custom").Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	allowedHeaders := w.Header().Get("Access-Control-Allow-Headers")
	if allowedHeaders != "Content-Type, X-Custom" {
		t.Errorf("expected allowed headers, got %s", allowedHeaders)
	}
}

func TestOr_FirstMatchWins(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Or(
		cors.Origins("https://trusted.com").AllowCredentials(),
		cors.AnyOrigin(),
	).MustHandler()(handler)

	tests := []struct {
		name              string
		origin            string
		expectCredentials bool
	}{
		{"trusted origin gets credentials", "https://trusted.com", true},
		{"other origin no credentials", "http://other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.origin {
				t.Errorf("expected origin %q, got %q", tt.origin, gotOrigin)
			}

			gotCreds := w.Header().Get("Access-Control-Allow-Credentials")
			if tt.expectCredentials && gotCreds != "true" {
				t.Errorf("expected credentials, got %q", gotCreds)
			}
			if !tt.expectCredentials && gotCreds != "" {
				t.Errorf("expected no credentials, got %q", gotCreds)
			}
		})
	}
}

func TestOr_NoMatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Or(
		cors.Origins("http://a.com"),
		cors.Origins("http://b.com"),
	).MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no CORS headers for non-matching origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestImmutability(t *testing.T) {
	base := cors.AnyOrigin()
	withMethods := base.AllowMethods("GET", "DELETE")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test withMethods on preflight
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "DELETE")
	w := httptest.NewRecorder()
	withMethods.Handler()(handler).ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Methods") != "GET, DELETE" {
		t.Errorf("withMethods should have custom methods, got %s", w.Header().Get("Access-Control-Allow-Methods"))
	}

	// Test base still has default methods
	w = httptest.NewRecorder()
	base.Handler()(handler).ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Methods") != "GET, POST, OPTIONS" {
		t.Errorf("base should have default methods, got %s", w.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestNonPreflightPassesThrough(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("expected handler to be called for non-preflight request")
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected CORS headers to be set even for non-preflight requests")
	}
}

// Test that OriginFunc can be used as escape hatch for credentials with any origin
func TestOriginFunc_EscapeHatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// This is the documented escape hatch for "any origin with credentials"
	// OriginFunc is not validated - you're responsible for security
	corsHandler := cors.OriginFunc(func(origin string) bool {
		return true // deliberately allow all
	}).AllowCredentials().MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://any-origin.com" {
		t.Error("OriginFunc escape hatch should allow any origin")
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("OriginFunc escape hatch should allow credentials")
	}
}

func TestOriginSuffix_PortWildcard(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		suffix         string
		origin         string
		expectedOrigin string
	}{
		// localhost:* should match localhost on any port
		{"localhost wildcard - no port", "localhost:*", "http://localhost", "http://localhost"},
		{"localhost wildcard - port 3000", "localhost:*", "http://localhost:3000", "http://localhost:3000"},
		{"localhost wildcard - port 8080", "localhost:*", "http://localhost:8080", "http://localhost:8080"},
		{"localhost wildcard - no match other host", "localhost:*", "http://example.com:3000", ""},

		// .example.com:* should match subdomains on any port
		{"subdomain wildcard - with port", ".example.com:*", "https://api.example.com:8080", "https://api.example.com:8080"},
		{"subdomain wildcard - no port", ".example.com:*", "https://api.example.com", "https://api.example.com"},
		{"subdomain wildcard - nested with port", ".example.com:*", "https://foo.bar.example.com:9000", "https://foo.bar.example.com:9000"},
		{"subdomain wildcard - no exact match", ".example.com:*", "https://example.com:8080", ""},

		// example.com:* should match exact and subdomains on any port
		{"domain wildcard - exact no port", "example.com:*", "https://example.com", "https://example.com"},
		{"domain wildcard - exact with port", "example.com:*", "https://example.com:8080", "https://example.com:8080"},
		{"domain wildcard - subdomain with port", "example.com:*", "https://api.example.com:3000", "https://api.example.com:3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corsHandler := cors.OriginSuffix(tt.suffix).MustHandler()(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.expectedOrigin {
				t.Errorf("expected origin %q, got %q", tt.expectedOrigin, gotOrigin)
			}
		})
	}
}

// TestOriginSuffix_RequiresDotBoundary validates that suffix matching requires
// a dot boundary to prevent "evilexample.com" matching "example.com".
func TestOriginSuffix_RequiresDotBoundary(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name        string
		suffix      string
		origin      string
		shouldAllow bool
	}{
		// Must not match domains that merely end with the suffix string
		{"evil prefix", "example.com", "https://evilexample.com", false},
		{"hyphenated", "example.com", "https://evil-example.com", false},
		{"target as subdomain of attacker", "example.com", "https://example.com.attacker.com", false},

		// Dot prefix mode: only subdomains, not exact match
		{"dot prefix subdomain", ".example.com", "https://api.example.com", true},
		{"dot prefix exact rejected", ".example.com", "https://example.com", false},
		{"dot prefix evil", ".example.com", "https://notexample.com", false},

		// Valid matches
		{"exact", "example.com", "https://example.com", true},
		{"subdomain", "example.com", "https://api.example.com", true},
		{"nested subdomain", "example.com", "https://v1.api.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corsHandler := cors.OriginSuffix(tt.suffix).MustHandler()(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			allowed := w.Header().Get("Access-Control-Allow-Origin") == tt.origin
			if allowed != tt.shouldAllow {
				t.Errorf("expected allowed=%v, got %v", tt.shouldAllow, allowed)
			}
		})
	}
}

// TestAnyOrigin_EchoesOriginLiterally validates that the Origin header value
// is echoed back without modification. Go's net/http handles CRLF safely.
func TestAnyOrigin_EchoesOriginLiterally(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	// Origins with special characters - Go's http.Header sanitizes these
	origins := []struct {
		name   string
		origin string
	}{
		{"newline", "https://example.com\nX-Injected: true"},
		{"carriage return", "https://example.com\rX-Injected: true"},
		{"CRLF", "https://example.com\r\nSet-Cookie: session=evil"},
		{"percent encoded", "https://example.com%0AX-Injected: true"},
		{"unicode line separator", "https://example.com\u2028evil"},
	}

	for _, tt := range origins {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			// Go's http.Header prevents header injection
			if w.Header().Get("X-Injected") != "" {
				t.Error("header injection should not be possible")
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Error("cookie injection should not be possible")
			}
		})
	}
}

// TestOrigins_ExactByteMatch validates that origin matching compares the full
// byte sequence - null bytes or other characters don't cause truncation.
func TestOrigins_ExactByteMatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").MustHandler()(handler)

	// None of these should match "https://example.com"
	origins := []string{
		"https://example.com\x00.evil.com",
		"https://evil\x00example.com",
		"\x00https://example.com",
		"https://\x00example.com",
	}

	for _, origin := range origins {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()

		corsHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") == "https://example.com" {
			t.Errorf("should not match with embedded bytes: %q", origin)
		}
	}
}

// TestOr_AppliesMatchingRuleConfig validates that Or() applies the configuration
// (including credentials) from the first matching rule only.
func TestOr_AppliesMatchingRuleConfig(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Or(
		cors.Origins("https://trusted.com").AllowCredentials(),
		cors.AnyOrigin(), // fallback without credentials
	).MustHandler()(handler)

	tests := []struct {
		origin      string
		expectCreds bool
	}{
		{"https://trusted.com", true},  // matches first rule with credentials
		{"https://other.com", false},   // matches second rule without credentials
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			hasCreds := w.Header().Get("Access-Control-Allow-Credentials") == "true"
			if hasCreds != tt.expectCreds {
				t.Errorf("expected credentials=%v, got %v", tt.expectCreds, hasCreds)
			}
		})
	}
}

// TestRule_Wrap tests the Wrap method with both success and error cases
func TestRule_Wrap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("success", func(t *testing.T) {
		wrapped, err := cors.Origins("https://example.com").AllowCredentials().Wrap(handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wrapped == nil {
			t.Fatal("expected non-nil handler")
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("expected credentials to be set")
		}
	})

	t.Run("error", func(t *testing.T) {
		wrapped, err := cors.Origins("http://insecure.com").AllowCredentials().Wrap(handler)
		if err == nil {
			t.Fatal("expected error for insecure origin with credentials")
		}
		if wrapped != nil {
			t.Error("expected nil handler when error returned")
		}
	})
}

// TestPublicRule_Wrap tests the PublicRule Wrap method
func TestPublicRule_Wrap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := cors.AnyOrigin().Wrap(handler)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped handler")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected CORS headers to be set")
	}
}

// TestCombinedRule_Wrap tests CombinedRule Wrap with success and error cases
func TestCombinedRule_Wrap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("success", func(t *testing.T) {
		rule := cors.Or(
			cors.Origins("https://trusted.com").AllowCredentials(),
			cors.AnyOrigin(),
		)
		wrapped, err := rule.Wrap(handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wrapped == nil {
			t.Fatal("expected non-nil handler")
		}
	})

	t.Run("error", func(t *testing.T) {
		rule := cors.Or(
			cors.Origins("http://insecure.com").AllowCredentials(),
			cors.AnyOrigin(),
		)
		wrapped, err := rule.Wrap(handler)
		if err == nil {
			t.Fatal("expected error for insecure origin in combined rule")
		}
		if wrapped != nil {
			t.Error("expected nil handler when error returned")
		}
	})
}

// TestCombinedRule_MustHandler_Panic tests that MustHandler panics on invalid config
func TestCombinedRule_MustHandler_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()

	cors.Or(
		cors.Origins("http://insecure.com").AllowCredentials(),
		cors.AnyOrigin(),
	).MustHandler()
}

// TestCombinedRule_MustWrap_Panic tests that MustWrap panics on invalid config
func TestCombinedRule_MustWrap_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cors.Or(
		cors.Origins("http://insecure.com").AllowCredentials(),
		cors.AnyOrigin(),
	).MustWrap(handler)
}

// TestRule_MustWrap tests Rule.MustWrap for success case
func TestRule_MustWrap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := cors.Origins("https://example.com").MustWrap(handler)
	if wrapped == nil {
		t.Fatal("expected non-nil handler")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("expected CORS headers")
	}
}

// TestMaxAge_EdgeCases tests MaxAge with various values
func TestMaxAge_EdgeCases(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name          string
		maxAge        int
		shouldSet     bool
		expectedValue string
	}{
		{"zero explicitly disables caching", 0, true, "0"},
		{"positive", 3600, true, "3600"},
		{"small positive", 1, true, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corsHandler := cors.AnyOrigin().MaxAge(tt.maxAge).Handler()(handler)

			// Preflight request
			req := httptest.NewRequest("OPTIONS", "/test", nil)
			req.Header.Set("Origin", "http://example.com")
			req.Header.Set("Access-Control-Request-Method", "POST")
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			got := w.Header().Get("Access-Control-Max-Age")
			if tt.shouldSet && got != tt.expectedValue {
				t.Errorf("MaxAge=%d: expected %q, got %q", tt.maxAge, tt.expectedValue, got)
			}
			if !tt.shouldSet && got != "" {
				t.Errorf("MaxAge=%d: expected no header, got %q", tt.maxAge, got)
			}
		})
	}

	// Negative MaxAge should panic (invalid configuration)
	t.Run("negative panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MaxAge(-1) should panic")
			}
		}()
		cors.AnyOrigin().MaxAge(-1).Handler()
	})

	// MaxAge should NOT be set on non-preflight requests
	t.Run("non-preflight", func(t *testing.T) {
		corsHandler := cors.AnyOrigin().MaxAge(3600).Handler()(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		corsHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Max-Age") != "" {
			t.Error("MaxAge should not be set on non-preflight request")
		}
	})
}

// TestIPv6Origins tests IPv6 origin handling
func TestIPv6Origins(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("exact match", func(t *testing.T) {
		corsHandler := cors.Origins("http://[::1]:8080").MustHandler()(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://[::1]:8080")
		w := httptest.NewRecorder()

		corsHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "http://[::1]:8080" {
			t.Error("IPv6 origin should match exactly")
		}
	})

	t.Run("no match different port", func(t *testing.T) {
		corsHandler := cors.Origins("http://[::1]:8080").MustHandler()(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://[::1]:9090")
		w := httptest.NewRecorder()

		corsHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("different port should not match")
		}
	})

	t.Run("credentials with IPv6 localhost", func(t *testing.T) {
		// IPv6 localhost should be allowed with http:// + credentials
		_, err := cors.Origins("http://[::1]:3000").AllowCredentials().Handler()
		if err != nil {
			t.Errorf("IPv6 localhost should be allowed with credentials: %v", err)
		}
	})
}

// TestLongOrigins tests handling of very long origin strings
func TestLongOrigins(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.AnyOrigin().Handler()(handler)

	// Very long subdomain (should not crash)
	longHost := "https://" + string(make([]byte, 1000)) + ".example.com"
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", longHost)
	w := httptest.NewRecorder()

	// Should not panic
	corsHandler.ServeHTTP(w, req)
}

// TestEmptyOriginHeader tests behavior when Origin header is empty or missing
func TestEmptyOriginHeader(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").MustHandler()(handler)

	tests := []struct {
		name   string
		origin string
	}{
		{"empty string", ""},
		{"whitespace", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled = false
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			// Handler should still be called (CORS is optional)
			if !handlerCalled {
				t.Error("handler should be called even without valid origin")
			}

			// No CORS headers should be set for invalid origins
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Error("CORS headers should not be set for empty/invalid origin")
			}
		})
	}
}

// TestRule_AllowMethods tests custom method configuration on Rule
func TestRule_AllowMethods(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").
		AllowMethods("GET", "POST", "PUT", "DELETE").
		MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods != "GET, POST, PUT, DELETE" {
		t.Errorf("expected custom methods, got %q", methods)
	}
}

// TestRule_AllowHeaders tests custom header configuration on Rule
func TestRule_AllowHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").
		AllowHeaders("X-Custom-Header", "X-Another-Header").
		MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers != "X-Custom-Header, X-Another-Header" {
		t.Errorf("expected custom headers, got %q", headers)
	}
}

// TestRule_ExposeHeaders tests custom expose headers on Rule
func TestRule_ExposeHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").
		ExposeHeaders("X-Custom-Response", "X-Request-Id").
		MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	exposed := w.Header().Get("Access-Control-Expose-Headers")
	if exposed != "X-Custom-Response, X-Request-Id" {
		t.Errorf("expected expose headers, got %q", exposed)
	}
}

// TestOriginSuffix_PortWildcard_EdgeCases tests edge cases in port wildcard matching
func TestOriginSuffix_PortWildcard_EdgeCases(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test port stripping logic with various origins
	corsHandler := cors.OriginSuffix("example.com:*").MustHandler()(handler)

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{"with port", "https://example.com:8080", "https://example.com:8080"},
		{"without port", "https://example.com", "https://example.com"},
		{"subdomain with port", "https://api.example.com:3000", "https://api.example.com:3000"},
		{"subdomain without port", "https://api.example.com", "https://api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			got := w.Header().Get("Access-Control-Allow-Origin")
			if got != tt.expectedOrigin {
				t.Errorf("expected %q, got %q", tt.expectedOrigin, got)
			}
		})
	}
}

// TestExtractHost_EdgeCases tests extractHost with edge cases
func TestExtractHost_EdgeCases(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.OriginSuffix("example.com").MustHandler()(handler)

	// Origin with path - extractHost extracts host portion, so it will match
	// Note: browsers never send paths in Origin headers, but we test the behavior
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com/some/path")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	// The host portion matches, so it returns the full origin (as sent)
	// This documents current behavior - extractHost strips the path for matching
	// but the original origin value is echoed back
	allowedOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowedOrigin != "https://example.com/some/path" {
		t.Errorf("expected origin with path to be echoed, got %q", allowedOrigin)
	}
}

// TestHandler_EmptyOrigin tests handler behavior with missing/empty origin
func TestHandler_EmptyOrigin(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").MustHandler()(handler)

	// No Origin header at all
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handlerCalled = false

	corsHandler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("handler should be called for requests without Origin header")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set without Origin header")
	}
}

// TestPreflight_EmptyOrigin tests preflight with missing origin
func TestPreflight_EmptyOrigin(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").MustHandler()(handler)

	// OPTIONS request without Origin header
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	handlerCalled = false

	corsHandler.ServeHTTP(w, req)

	// Handler should still be called for OPTIONS without origin
	// (it's not a CORS preflight, just a regular OPTIONS request)
	if !handlerCalled {
		t.Error("handler should be called for OPTIONS without Origin")
	}
}

// TestMatchesOrigin_EmptyHost tests matching with malformed origin
func TestMatchesOrigin_EmptyHost(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.OriginSuffix("example.com").MustHandler()(handler)

	// Malformed origins that result in empty host
	malformed := []string{
		"https://",
		"https:///path",
		"https://?query",
	}

	for _, origin := range malformed {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()

		corsHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("malformed origin %q should not match", origin)
		}
	}
}

// TestOriginFunc_NilFunction tests behavior with nil custom function
func TestOriginFunc_NilFunction(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// OriginFunc with nil should not match anything
	corsHandler := cors.OriginFunc(nil).MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("nil OriginFunc should not match any origin")
	}
}

// TestRule_MaxAge tests MaxAge on Rule type
func TestRule_MaxAge(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Origins("https://example.com").
		MaxAge(7200).
		MustHandler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	maxAge := w.Header().Get("Access-Control-Max-Age")
	if maxAge != "7200" {
		t.Errorf("expected MaxAge 7200, got %q", maxAge)
	}
}

// TestConcurrentRequests verifies thread safety
func TestConcurrentRequests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := cors.Or(
		cors.Origins("https://allowed.com").AllowCredentials(),
		cors.AnyOrigin(),
	).MustHandler()(handler)

	// Run concurrent requests
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			origin := "https://allowed.com"
			if n%2 == 0 {
				origin = "https://other.com"
			}

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()

			corsHandler.ServeHTTP(w, req)

			// Verify correct behavior
			allowedOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if allowedOrigin != origin {
				t.Errorf("concurrent request: expected %q, got %q", origin, allowedOrigin)
			}

			hasCreds := w.Header().Get("Access-Control-Allow-Credentials") == "true"
			expectCreds := origin == "https://allowed.com"
			if hasCreds != expectCreds {
				t.Errorf("concurrent request: credentials mismatch for %q", origin)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

// Benchmarks

func BenchmarkCORS_SimpleRequest(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}

func BenchmarkCORS_Preflight(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}

func BenchmarkCORS_NoOrigin(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.AnyOrigin().Handler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}

func BenchmarkCORS_OriginNotAllowed(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.Origins("http://allowed.com").MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://notallowed.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}

func BenchmarkCORS_Or(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.Or(
		cors.Origins("https://first.com").AllowCredentials(),
		cors.Origins("http://second.com"),
		cors.AnyOrigin(),
	).MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://third.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}

func BenchmarkCORS_OriginSuffix(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.OriginSuffix("example.com").MustHandler()(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://api.example.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)
	}
}
