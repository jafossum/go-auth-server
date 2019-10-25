package middleware

import (
	"net/http"

	"github.com/jafossum/go-auth-server/utils/logger"
)

// APIKey -  ApiKey authorization middleware
func APIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if key == "SomeSuperSecretApiKey" {
			logger.Info.Println("Authenticated api key")
			// Pass down the request to the next middleware (or final handler)
			next.ServeHTTP(w, r)
		} else {
			logger.Warning.Printf("Access forbiden with ApiKey: %s", key)
			// Write an error and stop the handler chain
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	})
}
