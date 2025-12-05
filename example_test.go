package cors_test

import (
	"fmt"
	"net/http"

	"github.com/ahimsalabs/cors"
)

func ExampleAnyOrigin() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// Allow all origins (suitable for public APIs)
	// Note: AnyOrigin() returns PublicRule which does NOT have AllowCredentials()
	mux := http.NewServeMux()
	mux.Handle("/", cors.AnyOrigin().Wrap(handler))
}

func ExampleOrigins() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// Allow only specific origins (can use AllowCredentials)
	// Use MustWrap for examples/tests; use Wrap with error handling in production
	mux := http.NewServeMux()
	mux.Handle("/", cors.Origins(
		"https://app.example.com",
		"https://admin.example.com",
	).AllowCredentials().MustWrap(handler))
}

func ExampleOriginSuffix() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// "example.com" matches example.com AND *.example.com
	// ".example.com" matches only *.example.com (subdomains only)
	mux := http.NewServeMux()
	mux.Handle("/", cors.OriginSuffix("example.com").MustWrap(handler))
}

func ExampleOriginFunc() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// Custom origin matching logic - escape hatch for complex scenarios
	// This is the only way to use AllowCredentials with dynamic origins
	mux := http.NewServeMux()
	mux.Handle("/", cors.OriginFunc(func(origin string) bool {
		// Your custom logic here (e.g., database lookup)
		return origin == "https://allowed.com"
	}).AllowCredentials().MustWrap(handler))
}

func ExampleOr() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// Different policies for different origins:
	// - Trusted origins get credentials
	// - Everything else is allowed without credentials
	mux := http.NewServeMux()
	mux.Handle("/", cors.Or(
		cors.Origins("https://trusted.com").AllowCredentials(),
		cors.AnyOrigin(), // fallback, no credentials
	).MustWrap(handler))
}
