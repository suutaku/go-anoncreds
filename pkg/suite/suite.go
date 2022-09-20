package suite

import (
	"crypto"

	"github.com/suutaku/go-anoncreds/pkg/credential"
)

// SignatureSuite encapsulates signature suite methods required for signature verification.
type SignatureSuite interface {

	// // GetCanonicalDocument will return normalized/canonical version of the document
	// GetCanonicalDocument(doc interface{}) ([]byte, error)

	// // GetDigest returns document digest
	// GetDigest(doc []byte) []byte

	// Verify will verify signature against public key
	Verify(pubKey crypto.PublicKey, doc []byte, signature []byte) error

	// another compact method
	VerifyProof(cred *credential.Credential, resolver PublicKeyResolver) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool
}
