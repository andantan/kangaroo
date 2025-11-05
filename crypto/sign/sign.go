package sign

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
)

func Sign(
	signer key.PrivateKey,
	item key.Signable,
	hasher hash.HashDeriver,
) (key.Signature, error) {
	h, err := item.HashForSigning(hasher)
	if err != nil {
		return nil, fmt.Errorf("failed to hash: %w", err)
	}

	sig, err := signer.Sign(h.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return sig, nil
}

func VerifySignature(
	pubKey key.PublicKey,
	sig key.Signature,
	hash hash.Hash,
) error {
	if pubKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	if sig == nil {
		return fmt.Errorf("signature cannot be nil")
	}
	if hash == nil {
		return fmt.Errorf("hash cannot be nil")
	}

	if pubKey.Type() != sig.Type() {
		return fmt.Errorf("key type (%s) does not match signature type (%s)", pubKey.Type(), sig.Type())
	}

	if !sig.Verify(pubKey, hash.Bytes()) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
