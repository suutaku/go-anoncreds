package verifier

import "crypto"

type Verifier interface {
	// Verify will verify a signature.
	Verify(pubKeyValue crypto.PublicKey, doc, signature []byte) error
}
