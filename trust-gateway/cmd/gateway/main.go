package main

import (
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"

	"github.com/FrancoBorba/open-finance-trust-ledger/trust-gateway/internal/mtls"
)

func main() {
	caCertPath := filepath.Join("infra", "certs", "ca.crt")
	serverCertPath := filepath.Join("infra", "certs", "server.crt")
	serverKeyPath := filepath.Join("infra", "certs", "server.key")

	tlsConfig, err := mtls.BuildServerTLSConfig(caCertPath)
	if err != nil {
		log.Fatalf("Falha ao construir a configuração mTLS: %v", err)
	}

	mux := http.NewServeMux()
	
	mux.HandleFunc("/mtls/whoami", func(w http.ResponseWriter, r *http.Request) {
		identity, ok := mtls.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "Identidade não encontrada no contexto", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(identity)
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mtls.Middleware(mux),
		TLSConfig: tlsConfig,
	}

	log.Println("Trust Gateway iniciado em https://localhost:8443 (mTLS ICP-Brasil estrito HABILITADO)")
	

	if err := server.ListenAndServeTLS(serverCertPath, serverKeyPath); err != nil {
		log.Fatalf("Erro no servidor: %v", err)
	}
}