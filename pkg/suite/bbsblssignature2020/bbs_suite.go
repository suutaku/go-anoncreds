package bbsblssignature2020

import (
	"crypto"

	"github.com/suutaku/go-anoncreds/pkg/credential"
	"github.com/suutaku/go-anoncreds/pkg/suite"
)

const (
	SignatureType = "BbsBlsSignature2020"
)

type BBSSuite struct {
	Verifier       *BBSVerifier
	Signer         *BBSSigner
	CompactedProof bool
}

func NewBBSSuite(ver *BBSVerifier, sigr *BBSSigner, compated bool) *BBSSuite {
	return &BBSSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
	}
}

// // GetCanonicalDocument will return normalized/canonical version of the document
// func (bbss *BBSSuite) GetCanonicalDocument(doc interface{}) ([]byte, error) {
// 	ldOptions := ld.NewJsonLdOptions("")
// 	ldOptions.ProcessingMode = ld.JsonLd_1_1
// 	ldOptions.Algorithm = rdfDataSetAlg
// 	ldOptions.Format = "application/n-quads"
// 	ldOptions.ProduceGeneralizedRdf = true
// 	view, err := bbss.jsonldProcessor.Normalize(doc, ldOptions)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
// 	}

// 	result, ok := view.(string)
// 	if !ok {
// 		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
// 	}

// 	return []byte(result), nil
// }

// // GetDigest returns document digest
// func (bbss *BBSSuite) GetDigest(doc []byte) []byte {
// 	return doc
// }

// Verify will verify signature against public key
func (bbss *BBSSuite) Verify(pubKey crypto.PublicKey, doc []byte, signature []byte) error {
	return bbss.Verifier.Verify(pubKey, doc, signature)
}

// another compact method
func (bbss *BBSSuite) VerifyProof(cred *credential.Credential, resolver *suite.PublicKeyResolver) error {
	return bbss.Verifier.VerifyProof(cred, resolver)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSSuite) Accept(signatureType string) bool {
	return signatureType == SignatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSSuite) CompactProof() bool {
	return bbss.CompactedProof
}
