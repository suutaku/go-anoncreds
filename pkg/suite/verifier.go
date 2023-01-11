package suite

type Verifier interface {
	// Verify will verify a signature.
	Verify(pub []byte, doc, signature, nonce []byte) error
}
