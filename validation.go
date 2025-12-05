package cors

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Forbidden methods per Fetch spec - browsers will never send these via CORS.
// See: https://fetch.spec.whatwg.org/#methods
var forbiddenMethods = map[string]bool{
	"CONNECT": true,
	"TRACE":   true,
	"TRACK":   true,
}

// Forbidden request headers per Fetch spec - browsers cannot set these.
// Allowing them in CORS config is misleading since they'll never be sent.
// See: https://fetch.spec.whatwg.org/#forbidden-header-name
var forbiddenRequestHeaders = map[string]bool{
	"accept-charset":               true,
	"accept-encoding":              true,
	"access-control-request-headers": true,
	"access-control-request-method":  true,
	"connection":                   true,
	"content-length":               true,
	"cookie":                       true,
	"cookie2":                      true,
	"date":                         true,
	"dnt":                          true,
	"expect":                       true,
	"host":                         true,
	"keep-alive":                   true,
	"origin":                       true,
	"referer":                      true,
	"te":                           true,
	"trailer":                      true,
	"transfer-encoding":            true,
	"upgrade":                      true,
	"via":                          true,
}

// validate checks the config for security issues.
func (c *config) validate() error {
	// Validate max-age
	if c.maxAge != nil && *c.maxAge < 0 {
		return fmt.Errorf("invalid MaxAge %d: must be non-negative", *c.maxAge)
	}

	// Validate methods
	for _, method := range c.allowMethods {
		upper := strings.ToUpper(method)
		if forbiddenMethods[upper] {
			return fmt.Errorf("forbidden method %q: browsers will never send this via CORS", method)
		}
	}

	// Validate headers
	for _, header := range c.allowHeaders {
		lower := strings.ToLower(header)
		if forbiddenRequestHeaders[lower] {
			return fmt.Errorf("forbidden header %q: browsers cannot set this header", header)
		}
		// Check for Sec-* and Proxy-* prefixes
		if strings.HasPrefix(lower, "sec-") || strings.HasPrefix(lower, "proxy-") {
			return fmt.Errorf("forbidden header %q: browsers cannot set Sec-* or Proxy-* headers", header)
		}
	}

	if c.allowCredentials && c.matchType == matchExact {
		for origin := range c.origins {
			if err := validateOrigin(origin, true); err != nil {
				return err
			}
		}
	}

	if c.matchType == matchExact {
		for origin := range c.origins {
			if err := validateOrigin(origin, false); err != nil {
				return err
			}
		}
	}

	if c.matchType == matchSuffix {
		if isPublicSuffix(c.suffix) {
			return fmt.Errorf("dangerous suffix pattern %q is a public suffix; "+
				"use a more specific domain like %q",
				c.suffix, "example."+c.suffix)
		}
	}

	return nil
}

// isPublicSuffix checks if the given domain is a public suffix (eTLD).
func isPublicSuffix(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")

	if domain == "localhost" {
		return false
	}

	etld, _ := publicsuffix.PublicSuffix(domain)
	return etld == domain
}

// validateOrigin validates an origin for correctness and security.
// If checkCredentials is true, also validates it's safe for credentialed requests.
func validateOrigin(origin string, checkCredentials bool) error {
	// Reject "null" origin - fundamentally unsafe and spoofable
	// See: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
	if origin == "null" {
		return errors.New("origin \"null\" is prohibited; " +
			"it is fundamentally unsafe and can be spoofed by attackers")
	}

	for _, c := range origin {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return fmt.Errorf("origin contains whitespace: %q", origin)
		}
		if c >= 'A' && c <= 'Z' {
			return fmt.Errorf("origin must be lowercase (browsers normalize to lowercase): %s", origin)
		}
	}

	scheme, hostPort, ok := parseOriginParts(origin)
	if !ok {
		return fmt.Errorf("invalid origin format: %s", origin)
	}

	host, port := splitHostPort(hostPort)

	if scheme == "http" && port == "80" {
		return fmt.Errorf("default port 80 must be elided for http origins: %s; "+
			"use %s://%s instead", origin, scheme, host)
	}
	if scheme == "https" && port == "443" {
		return fmt.Errorf("default port 443 must be elided for https origins: %s; "+
			"use %s://%s instead", origin, scheme, host)
	}

	if port != "" {
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid port in origin: %s", origin)
		}
	}

	if checkCredentials {
		if scheme == "http" {
			if host != "localhost" && host != "127.0.0.1" && host != "::1" &&
				!strings.HasPrefix(host, "[::1]") {
				return errors.New("insecure origin " + origin + " with credentials; " +
					"use https:// or localhost (use OriginFunc to override)")
			}
		}
	}

	return nil
}

// parseOriginParts extracts scheme and host:port from an origin URL.
func parseOriginParts(origin string) (scheme, hostPort string, ok bool) {
	idx := strings.Index(origin, "://")
	if idx == -1 {
		return "", "", false
	}
	scheme = origin[:idx]
	hostPort = origin[idx+3:]

	if strings.ContainsAny(hostPort, "/?#") {
		return "", "", false
	}

	return scheme, hostPort, true
}

// splitHostPort splits a host:port string into host and port.
func splitHostPort(hostPort string) (host, port string) {
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.LastIndex(hostPort, "]:"); idx != -1 {
			return hostPort[:idx+1], hostPort[idx+2:]
		}
		return hostPort, ""
	}

	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx], hostPort[idx+1:]
	}
	return hostPort, ""
}
