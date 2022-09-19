package suite

type Signer interface {
	// Sign will sign document and return signature
	Sign(data [][]byte) ([]byte, error)
	// Alg return alg.
	Alg() string
}
