package wg

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GeneratePrivateKey returns a fresh random Curve25519 private key,
// base64-encoded as WireGuard configs expect.
func GeneratePrivateKey() (string, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return k.String(), nil
}

// PublicKey derives the base64 public key from a base64 private key.
func PublicKey(privateB64 string) (string, error) {
	priv, err := wgtypes.ParseKey(privateB64)
	if err != nil {
		return "", fmt.Errorf("invalid private key")
	}
	return priv.PublicKey().String(), nil
}
