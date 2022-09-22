package bbsblssignature2020

import (
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

const (
	SignatureType = "BbsBlsSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type BBSSuite struct {
	Verifier       suite.Verifier
	Signer         suite.Signer
	CompactedProof bool
}

func NewBBSSuite(ver *BBSG2SignatureVerifier, sigr *BBSSigner, compated bool) *BBSSuite {
	return &BBSSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSSuite) GetCanonicalDocument(doc interface{}) ([]byte, error) {
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = rdfDataSetAlg
	ldOptions.Format = "application/n-quads"
	ldOptions.ProduceGeneralizedRdf = true
	processor := ld.NewJsonLdProcessor()
	docMap := make(map[string]interface{})
	b, _ := json.Marshal(doc)
	json.Unmarshal(b, &docMap)
	view, err := processor.Normalize(docMap, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	return []byte(result), nil
}

// GetDigest returns document digest
func (bbss *BBSSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSSuite) Alg() string {
	return SignatureType
}

func (bbss *BBSSuite) Sign(docByte []byte) ([]byte, error) {

	return bbss.Signer.Sign([][]byte{docByte})
}

// Verify will verify signature against public key
func (bbss *BBSSuite) Verify(doc []byte, pubkeyBytes, signature []byte) error {
	pubKey, err := bbs.UnmarshalPublicKey(pubkeyBytes)
	if err != nil {
		return err
	}
	return bbss.Verifier.Verify(pubKey, doc, signature)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSSuite) Accept(signatureType string) bool {
	return signatureType == SignatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSSuite) CompactProof() bool {
	return bbss.CompactedProof
}
