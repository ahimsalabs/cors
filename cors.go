// Package cors provides CORS middleware with a fluent, composable API.
//
// Basic usage:
//
//	http.Handle("/api", cors.AnyOrigin().Wrap(handler))
//	http.Handle("/app", cors.Origins("https://app.com").MustWrap(handler))
//
// With error handling:
//
//	h, err := cors.Origins("https://app.com").AllowCredentials().Handler()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Multiple policies:
//
//	cors.Or(
//	    cors.Origins("https://trusted.com").AllowCredentials(),
//	    cors.AnyOrigin(),  // fallback without credentials
//	).MustHandler()
package cors

import (
	"fmt"
	"net/http"
	"strings"
)

// Default methods and headers applied to all rules.
// Methods: GET, POST, OPTIONS (OPTIONS required for preflight).
// Headers: Content-Type.
// Use AllowMethods/AllowHeaders to override. For authenticated APIs,
// add "Authorization" explicitly via AllowHeaders.
var (
	defaultAllowMethods = []string{"GET", "POST", "OPTIONS"}
	defaultAllowHeaders = []string{"Content-Type"}
)

// matchType discriminates origin matching strategy for zero-alloc dispatch.
type matchType int

const (
	matchAny    matchType = iota // matches all origins
	matchExact                   // matches origins in a set
	matchSuffix                  // matches origins with host suffix
	matchCustom                  // matches via custom function (1 alloc)
)

// config holds the internal CORS configuration.
type config struct {
	matchType        matchType
	origins          map[string]struct{} // for matchExact
	suffix           string              // for matchSuffix (without leading dot)
	suffixOnly       bool                // true if original had leading dot (subdomains only)
	portWildcard     bool                // true if any port is allowed (for suffix matching)
	customFn         func(string) bool   // for matchCustom
	allowCredentials bool
	allowMethods     []string
	allowHeaders     []string
	exposeHeaders    []string
	maxAge           *int // nil = not set, 0 = explicitly disable caching

	// Precomputed strings for zero-alloc request handling
	methodsStr       string
	headersStr       string
	exposeHeadersStr string
	maxAgeStr        string
}

func compileConfig(c *config) config {
	compiled := *c
	compiled.methodsStr = strings.Join(c.allowMethods, ", ")
	compiled.headersStr = strings.Join(c.allowHeaders, ", ")
	compiled.exposeHeadersStr = strings.Join(c.exposeHeaders, ", ")
	if c.maxAge != nil {
		compiled.maxAgeStr = fmt.Sprintf("%d", *c.maxAge)
	}
	return compiled
}

func buildHandler(c *config) func(http.Handler) http.Handler {
	compiled := compileConfig(c)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			origin := req.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, req)
				return
			}

			if !matchesOrigin(&compiled, origin) {
				next.ServeHTTP(w, req)
				return
			}

			applyHeaders(w, req, &compiled, origin)
			if req.Method == "OPTIONS" && req.Header.Get("Access-Control-Request-Method") != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, req)
		})
	}
}

func matchesOrigin(c *config, origin string) bool {
	switch c.matchType {
	case matchAny:
		return true
	case matchExact:
		_, ok := c.origins[origin]
		return ok
	case matchSuffix:
		host := extractHost(origin)
		if host == "" {
			return false
		}

		// For port wildcard matching, we need to strip the port from the origin's host
		matchHost := host
		if c.portWildcard {
			// Strip any port from the host for comparison
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				// Make sure it's not part of an IPv6 address
				if !strings.Contains(host, "[") || strings.HasSuffix(host[:idx], "]") {
					matchHost = host[:idx]
				}
			}
		}

		if c.suffixOnly {
			// ".example.com" - subdomains only
			return strings.HasSuffix(matchHost, "."+c.suffix)
		}
		// "example.com" - exact match OR subdomains
		return matchHost == c.suffix || strings.HasSuffix(matchHost, "."+c.suffix)
	case matchCustom:
		return c.customFn != nil && c.customFn(origin)
	}
	return false
}

// extractHost extracts the host from an origin URL without allocating.
// Origin format: scheme "://" host [ ":" port ]
func extractHost(origin string) string {
	_, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return ""
	}

	// Find end of host (port separator or end of string)
	if colonIdx := strings.IndexByte(rest, ':'); colonIdx != -1 {
		return rest[:colonIdx]
	}
	if slashIdx := strings.IndexByte(rest, '/'); slashIdx != -1 {
		return rest[:slashIdx]
	}
	return rest
}

func applyHeaders(w http.ResponseWriter, req *http.Request, c *config, origin string) {
	w.Header().Add("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if c.allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Preflight-specific headers
	if req.Method == "OPTIONS" && req.Header.Get("Access-Control-Request-Method") != "" {
		w.Header().Set("Access-Control-Allow-Methods", c.methodsStr)
		w.Header().Set("Access-Control-Allow-Headers", c.headersStr)
		if c.exposeHeadersStr != "" {
			w.Header().Set("Access-Control-Expose-Headers", c.exposeHeadersStr)
		}
		if c.maxAgeStr != "" {
			w.Header().Set("Access-Control-Max-Age", c.maxAgeStr)
		}
		return
	}

	// Non-preflight: expose headers if configured
	if c.exposeHeadersStr != "" {
		w.Header().Set("Access-Control-Expose-Headers", c.exposeHeadersStr)
	}
}

// containsHeader checks if a header exists in the list (case-insensitive).
func containsHeader(headers []string, target string) bool {
	target = strings.ToLower(target)
	for _, h := range headers {
		if strings.ToLower(h) == target {
			return true
		}
	}
	return false
}
