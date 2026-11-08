package mtls

import (
	"context"
	"net/http"
	"regexp"

	"github.com/google/uuid"
)

type contextKey string
const clientIdentityKey contextKey = "ofb_client_identity"

// The UUID regex validates the strict RFC 4122 format required by Open Finance Brasil.
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)


func Middleware(next http.Handler) http.Handler {

	return http.HandlerFunc( 
		func (w http.ResponseWriter , r *http.Request) {

			// search the x-fapi-interaction-id
			intereactionId := r.Header.Get("x-fapi-interaction-id") 

			// if is empty or does not match , return 400
			if intereactionId == "" || !uuidRegex.MatchString(intereactionId) {
				newId := uuid.New().String()
				w.Header().Set("x-fapi-interaction-id" , newId)
				http.Error(w, `{"errors":[{"code":"BAD_REQUEST","title":"Invalid Interaction ID","detail":"The x-fapi-interaction-id header is mandatory and must be a valid UUID (RFC4122)."}]}`, http.StatusBadRequest)
				return
			}

			// Mirrors the request ID
			w.Header().Set("x-fapi-interaction-id" , intereactionId)

			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED","title":"mTLS Required","detail":"Authentication header missing/invalid or token invalid."}]}`, http.StatusUnauthorized)
			return
		}


		leafCert := r.TLS.PeerCertificates[0]
		identity := ExtractClientIdentity(leafCert)

		ctx := context.WithValue(r.Context(), clientIdentityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// IdentityFromContext recupera a identidade validada do cliente a partir do contexto da requisição.
func IdentityFromContext(ctx context.Context) (ClientIdentity, bool) {
	id, ok := ctx.Value(clientIdentityKey).(ClientIdentity)
	return id, ok
}