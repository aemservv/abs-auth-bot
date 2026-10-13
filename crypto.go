package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// initCrypto initializes response signing.
func initCrypto() error {
	return initSigning()
}

// writeEncryptedJSON signs the payload and writes it as JSON.
func writeEncryptedJSON(w http.ResponseWriter, status int, payload any) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		b, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, `{"valid":false,"error":"encode failed"}`,
				http.StatusInternalServerError)
			return
		}
		var wrapped map[string]interface{}
		if err := json.Unmarshal(b, &wrapped); err != nil {
			http.Error(w, `{"valid":false,"error":"encode failed"}`,
				http.StatusInternalServerError)
			return
		}
		m = wrapped
	}

	signed := signResponse(m)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("Vary", "*")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(signed); err != nil {
		log.Printf("[WARN] write response: %v", err)
	}
}

// writeSignedError is kept for backwards compatibility with any callers
// that don't have a nonce handy. New code should use writeSignedErrorNonce.
func writeSignedError(w http.ResponseWriter, status int, msg string) {
	writeEncryptedJSON(w, status, map[string]interface{}{
		"valid": false,
		"error": msg,
		"ts":    time.Now().Unix(),
	})
}

// writeSignedErrorNonce is the correct helper. Every /api/validate error path
// must go through this so the client's nonce check always passes and the real
// error message reaches the user.
func writeSignedErrorNonce(w http.ResponseWriter, status int, msg, nonce, hwid string) {
	payload := map[string]interface{}{
		"valid": false,
		"error": msg,
		"ts":    time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if hwid != "" {
		payload["hwid"] = hwid
	}
	writeEncryptedJSON(w, status, payload)
}