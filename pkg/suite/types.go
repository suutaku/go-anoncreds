package suite

type DocVerificationData struct {
	RevealIndexes        []int
	RevealDocumentResult map[string]interface{}
	DocumentStatements   []string
}

type VerificationData struct {
	BlsMessages   [][]byte
	RevealIndexes []int
}
