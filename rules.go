package cors

import (
	"net/http"
	"strings"
)

// PublicRule is a CORS rule that allows any origin.
// It does not have [Rule.AllowCredentials] because allowing credentials
// with any origin is a security vulnerability (CORS spec violation).
// Use [OriginFunc] if you need this escape hatch.
type PublicRule struct {
	c config
}

// Rule is a CORS rule for specific origins.
// It supports [Rule.AllowCredentials] because specific origins are safe.
type Rule struct {
	c config
}

// OriginMatcher is implemented by origin matching rule types ([PublicRule] and [Rule]).
// It cannot be implemented outside this package.
type OriginMatcher interface {
	private()
}

func (PublicRule) private() {}
func (Rule) private()       {}

// AnyOrigin creates a rule that matches all origins.
// Returns [PublicRule] which does NOT have [Rule.AllowCredentials].
// This prevents the dangerous AnyOrigin + Credentials combination.
func AnyOrigin() PublicRule {
	return PublicRule{c: config{
		matchType:    matchAny,
		allowMethods: defaultAllowMethods,
		allowHeaders: defaultAllowHeaders,
	}}
}

// Origins creates a [Rule] that matches specific origins exactly.
func Origins(origins ...string) Rule {
	set := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		set[o] = struct{}{}
	}
	return Rule{c: config{
		matchType:    matchExact,
		origins:      set,
		allowMethods: defaultAllowMethods,
		allowHeaders: defaultAllowHeaders,
	}}
}

// OriginSuffix creates a [Rule] that matches origins by domain suffix.
//
// Patterns:
//
//	"example.com"    → example.com and *.example.com
//	".example.com"   → *.example.com only (subdomains)
//	"localhost:*"    → localhost on any port
//	".example.com:*" → *.example.com on any port
//
// Matching requires a dot boundary, preventing "evilexample.com" from matching "example.com".
func OriginSuffix(suffix string) Rule {
	// Check for port wildcard
	portWildcard := strings.HasSuffix(suffix, ":*")
	if portWildcard {
		suffix = suffix[:len(suffix)-2] // remove ":*"
	}

	suffixOnly := strings.HasPrefix(suffix, ".")
	if suffixOnly {
		suffix = suffix[1:] // remove leading dot for storage
	}
	return Rule{c: config{
		matchType:    matchSuffix,
		suffix:       suffix,
		suffixOnly:   suffixOnly,
		portWildcard: portWildcard,
		allowMethods: defaultAllowMethods,
		allowHeaders: defaultAllowHeaders,
	}}
}

// OriginFunc creates a [Rule] with a custom origin matching function.
// This is the escape hatch for complex scenarios including dynamic origins.
//
// Note: This allocates 1 object per request due to the function call.
// For static origins, prefer [Origins] or [OriginSuffix].
//
// Warning: If you use this with [Rule.AllowCredentials], ensure your function
// validates origins strictly. A function that returns true for all origins
// combined with credentials is a security vulnerability.
func OriginFunc(fn func(origin string) bool) Rule {
	return Rule{c: config{
		matchType:    matchCustom,
		customFn:     fn,
		allowMethods: defaultAllowMethods,
		allowHeaders: defaultAllowHeaders,
	}}
}

// CombinedRule is a set of rules combined with [Or]. The first matching rule wins.
type CombinedRule struct {
	rules []config
}

// Or combines multiple rules. The first matching rule wins.
// Accepts both [Rule] and [PublicRule].
//
// Example:
//
//	cors.Or(
//	    cors.Origins("https://trusted.com").AllowCredentials(),
//	    cors.AnyOrigin(),  // fallback without credentials
//	)
func Or(rules ...OriginMatcher) CombinedRule {
	configs := make([]config, len(rules))
	for i, r := range rules {
		switch v := r.(type) {
		case PublicRule:
			configs[i] = v.c
		case Rule:
			configs[i] = v.c
		}
	}
	return CombinedRule{rules: configs}
}

// AllowMethods returns a copy with the specified allowed methods.
func (r PublicRule) AllowMethods(methods ...string) PublicRule {
	r.c.allowMethods = methods
	return r
}

// AllowHeaders returns a copy with the specified allowed headers.
func (r PublicRule) AllowHeaders(headers ...string) PublicRule {
	r.c.allowHeaders = headers
	return r
}

// ExposeHeaders returns a copy with the specified exposed headers.
func (r PublicRule) ExposeHeaders(headers ...string) PublicRule {
	r.c.exposeHeaders = headers
	return r
}

// MaxAge returns a copy with the specified preflight cache duration in seconds.
// Use MaxAge(0) to explicitly disable preflight caching (overrides browser default).
func (r PublicRule) MaxAge(seconds int) PublicRule {
	r.c.maxAge = &seconds
	return r
}

// Handler returns the CORS middleware.
// Panics if configuration is invalid (e.g., forbidden methods/headers, negative MaxAge).
func (r PublicRule) Handler() func(http.Handler) http.Handler {
	if err := r.c.validate(); err != nil {
		panic("cors: " + err.Error())
	}
	return buildHandler(&r.c)
}

// Wrap directly wraps a handler with CORS middleware.
func (r PublicRule) Wrap(h http.Handler) http.Handler {
	return r.Handler()(h)
}

// AllowCredentials returns a copy with credentials enabled.
// When enabled, Access-Control-Allow-Credentials: true is sent,
// allowing browsers to send cookies and auth headers.
//
// This also adds "Authorization" to allowed headers if not already present,
// since most credentialed APIs use Bearer tokens.
func (r Rule) AllowCredentials() Rule {
	r.c.allowCredentials = true
	// Add Authorization header for Bearer token support
	if !containsHeader(r.c.allowHeaders, "Authorization") {
		r.c.allowHeaders = append(r.c.allowHeaders, "Authorization")
	}
	return r
}

// AllowMethods returns a copy with the specified allowed methods.
func (r Rule) AllowMethods(methods ...string) Rule {
	r.c.allowMethods = methods
	return r
}

// AllowHeaders returns a copy with the specified allowed headers.
func (r Rule) AllowHeaders(headers ...string) Rule {
	r.c.allowHeaders = headers
	return r
}

// ExposeHeaders returns a copy with the specified exposed headers.
func (r Rule) ExposeHeaders(headers ...string) Rule {
	r.c.exposeHeaders = headers
	return r
}

// MaxAge returns a copy with the specified preflight cache duration in seconds.
// Use MaxAge(0) to explicitly disable preflight caching (overrides browser default).
func (r Rule) MaxAge(seconds int) Rule {
	r.c.maxAge = &seconds
	return r
}

// Handler returns the CORS middleware.
// Returns an error if the configuration is invalid.
//
// For scripts and tests where panics are acceptable, use MustHandler instead.
func (r Rule) Handler() (func(http.Handler) http.Handler, error) {
	if err := r.c.validate(); err != nil {
		return nil, err
	}
	return buildHandler(&r.c), nil
}

// MustHandler returns the CORS middleware, panicking if the configuration
// is invalid. Use this for variable initialization and tests:
//
//	var corsHandler = cors.Origins("https://app.com").MustHandler()
//
// For production code that cannot tolerate panics, use Handler instead.
func (r Rule) MustHandler() func(http.Handler) http.Handler {
	h, err := r.Handler()
	if err != nil {
		panic("cors: " + err.Error())
	}
	return h
}

// Wrap directly wraps a handler with CORS middleware.
// Returns an error if the configuration is invalid.
func (r Rule) Wrap(h http.Handler) (http.Handler, error) {
	mw, err := r.Handler()
	if err != nil {
		return nil, err
	}
	return mw(h), nil
}

// MustWrap directly wraps a handler with CORS middleware, panicking if
// the configuration is invalid.
func (r Rule) MustWrap(h http.Handler) http.Handler {
	return r.MustHandler()(h)
}

// Handler returns the CORS middleware.
// Returns an error if any rule has invalid configuration.
func (cr CombinedRule) Handler() (func(http.Handler) http.Handler, error) {
	// Validate all rules
	for i := range cr.rules {
		if err := cr.rules[i].validate(); err != nil {
			return nil, err
		}
	}

	// Compile all rules
	compiled := make([]config, len(cr.rules))
	for i := range cr.rules {
		compiled[i] = compileConfig(&cr.rules[i])
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			origin := req.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, req)
				return
			}

			// Find first matching rule
			var matched *config
			for i := range compiled {
				if matchesOrigin(&compiled[i], origin) {
					matched = &compiled[i]
					break
				}
			}

			if matched == nil {
				next.ServeHTTP(w, req)
				return
			}

			applyHeaders(w, req, matched, origin)
			if req.Method == "OPTIONS" && req.Header.Get("Access-Control-Request-Method") != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, req)
		})
	}, nil
}

// MustHandler returns the CORS middleware, panicking if any rule configuration
// is invalid.
func (cr CombinedRule) MustHandler() func(http.Handler) http.Handler {
	h, err := cr.Handler()
	if err != nil {
		panic("cors: " + err.Error())
	}
	return h
}

// Wrap directly wraps a handler with CORS middleware.
// Returns an error if any rule configuration is invalid.
func (cr CombinedRule) Wrap(h http.Handler) (http.Handler, error) {
	mw, err := cr.Handler()
	if err != nil {
		return nil, err
	}
	return mw(h), nil
}

// MustWrap directly wraps a handler with CORS middleware, panicking if
// any rule configuration is invalid.
func (cr CombinedRule) MustWrap(h http.Handler) http.Handler {
	return cr.MustHandler()(h)
}
