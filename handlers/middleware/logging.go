package middleware

import (
	"net/http"

	"github.com/jafossum/go-auth-server/utils/logger"
)

// LoggingMiddleware - Logg handling for all requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		logger.Info.Println(r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}
