package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Ed25519 response signing
//
// The server signs every JSON response. The client embeds the matching public
// key and refuses to trust any response without a valid signature.
//
// Configure via env:
//   AUTH_SIGNING_PRIVKEY_B64  — base64 of 64-byte ed25519 private key
//   AUTH_SIGNING_PUBKEY_B64   — base64 of 32-byte ed25519 public key
//
// Generate a keypair:
//   go run ./cmd/genkey   (see repo for the tiny helper)
// ---------------------------------------------------------------------------

var (
	signingPriv ed25519.PrivateKey
	signingPub  ed25519.PublicKey
	signInit    sync.Once
	signInitErr error

	nonceMu    sync.Mutex
	nonceStore = make(map[string]time.Time)
)

const nonceWindow = 2 * time.Minute

func initSigning() error {
	signInit.Do(func() {
		privB64 := os.Getenv("AUTH_SIGNING_PRIVKEY_B64")
		pubB64 := os.Getenv("AUTH_SIGNING_PUBKEY_B64")

		if privB64 != "" && pubB64 != "" {
			priv, e1 := base64.StdEncoding.DecodeString(privB64)
			pub, e2 := base64.StdEncoding.DecodeString(pubB64)
			if e1 != nil || e2 != nil {
				signInitErr = fmt.Errorf("decode signing keys: %v / %v", e1, e2)
				return
			}
			if len(priv) != ed25519.PrivateKeySize {
				signInitErr = fmt.Errorf("bad priv key size: %d", len(priv))
				return
			}
			if len(pub) != ed25519.PublicKeySize {
				signInitErr = fmt.Errorf("bad pub key size: %d", len(pub))
				return
			}
			signingPriv = ed25519.PrivateKey(priv)
			signingPub = ed25519.PublicKey(pub)
			log.Printf("🔐 Response signing enabled (pubkey %s…)", pubB64[:12])
			return
		}

		// No keys provided — generate ephemeral ones and warn loudly.
		// The client will reject every response until you set real keys.
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			signInitErr = e
			return
		}
		signingPriv = priv
		signingPub = pub
		log.Println("⚠️  AUTH_SIGNING_PRIVKEY_B64 not set — using EPHEMERAL key.")
		log.Println("⚠️  Client will reject all responses until you set real keys.")
		log.Printf("⚠️  Ephemeral pubkey: %s", base64.StdEncoding.EncodeToString(pub))
	})
	return signInitErr
}

// signResponse returns a copy of payload with a "sig" field added.
// The signature covers the canonical JSON of payload WITHOUT "sig".
func signResponse(payload map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		if k == "sig" {
			continue
		}
		out[k] = v
	}

	blob, err := json.Marshal(out) // Go sorts map keys deterministically
	if err != nil {
		return map[string]interface{}{"valid": false, "error": "signing failed"}
	}
	sig := ed25519.Sign(signingPriv, blob)
	out["sig"] = base64.StdEncoding.EncodeToString(sig)
	return out
}

// checkNonce returns true if nonce is fresh and unused.
func checkNonce(nonce string) bool {
	if len(nonce) < 16 || len(nonce) > 128 {
		return false
	}
	nonceMu.Lock()
	defer nonceMu.Unlock()

	now := time.Now()
	for k, t := range nonceStore {
		if now.Sub(t) > nonceWindow {
			delete(nonceStore, k)
		}
	}
	if _, seen := nonceStore[nonce]; seen {
		return false
	}
	nonceStore[nonce] = now
	return true
}

func pubkeyB64() string {
	return base64.StdEncoding.EncodeToString(signingPub)
}