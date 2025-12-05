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

## License

MIT
