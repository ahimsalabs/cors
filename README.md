# cors

[![Go Reference](https://pkg.go.dev/badge/github.com/ahimsalabs/cors.svg)](https://pkg.go.dev/github.com/ahimsalabs/cors)

A fluent, zero-allocation CORS middleware for Go.

```go
import "github.com/ahimsalabs/cors"
```
![IDE autocomplete showing PublicRule has no AllowCredentials method](doc/screenshot.png)

## Usage

```go
// Public API
http.Handle("/api", cors.AnyOrigin().Wrap(handler))

// Authenticated API
cors.Origins("https://app.example.com").AllowCredentials().MustHandler()

// Multiple policies (first match wins)
cors.Or(
    cors.Origins("https://trusted.com").AllowCredentials(),
    cors.AnyOrigin(),
).MustHandler()
```

## Origin Matchers

| Function | Description |
|----------|-------------|
| `AnyOrigin()` | All origins. Returns `PublicRule` (credentials disabled). |
| `Origins(...)` | Exact origin match. |
| `OriginSuffix("example.com")` | `example.com` and `*.example.com` |
| `OriginSuffix(".example.com")` | `*.example.com` only |
| `OriginSuffix("localhost:*")` | `localhost` on any port |
| `OriginFunc(fn)` | Custom matching (escape hatch) |
| `Or(rules...)` | First match wins |

## Configuration

```go
cors.Origins("https://app.com").
    AllowCredentials().              // cookies + adds Authorization header
    AllowMethods("GET", "POST").     // default: GET, POST, OPTIONS
    AllowHeaders("X-Custom").        // default: Content-Type
    ExposeHeaders("X-Request-Id").
    MaxAge(3600).                    // preflight cache seconds; 0 disables
    MustHandler()
```

```go
c := cors.AnyOrigin().MustHandler()

mux.Handle("/", c(handler))  // net/http
r.Use(c)                     // chi, echo, etc.

// or wrap a single handler directly
http.Handle("/api", cors.AnyOrigin().MustWrap(handler))
```

## Security

**Compile-time:** `AnyOrigin()` returns `PublicRule` without `AllowCredentials()` (see pic above)

**Validation** rejects:
- `http://` origins with credentials (except localhost)
- Public suffix patterns (`OriginSuffix("github.io")`)
- `null` origin
- Default ports (`https://example.com:443`)
- Uppercase origins
- Forbidden methods (`CONNECT`, `TRACE`, `TRACK`)
- Forbidden headers (`Host`, `Origin`, `Cookie`, `Sec-*`, `Proxy-*`)
- Negative `MaxAge`

IDN domains must use punycode.

## References & Acknowledgments

This package was informed by:

- [**jub0bs/cors**](https://github.com/jub0bs/cors) - A production-grade CORS library with radix tree pattern matching (efficient for 100s of origins), structured errors for multi-tenant SaaS, IDNA validation, atomic reconfiguration, and comprehensive Fetch spec compliance. If you need those features or prefer declarative config over fluent APIs, use jub0bs/cors. Consider [sponsoring Julien's work](https://github.com/sponsors/jub0bs).
- Julien's blog post [*Fearless CORS*](https://jub0bs.com/posts/2023-02-08-fearless-cors/) - Comprehensive analysis of CORS security pitfalls
- [Fetch Living Standard](https://fetch.spec.whatwg.org/) - Defines forbidden methods and headers
- [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) - The Web Origin Concept (default port elision)
- [PortSwigger Research](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) - "null" origin vulnerability

This package uses a different API design (fluent builder with compile-time safety via types) but implements the same security validations as jub0bs/cors where applicable.

## License

MIT
