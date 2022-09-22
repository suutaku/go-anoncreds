package suite

// SignatureSuite encapsulates signature suite methods required for signature verification.
type SignatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc interface{}) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	Sign(doc []byte) ([]byte, error)

	// Verify will verify signature against public key
	Verify(doc []byte, pubkey, signature []byte) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool

	// Alg will return algorithm
	Alg() string
}
