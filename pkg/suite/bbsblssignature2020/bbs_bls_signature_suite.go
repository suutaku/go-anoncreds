package bbsblssignature2020

import (
	"encoding/json"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
)

const (
	SignatureType = "BbsBlsSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type BBSSuite struct {
	Verifier       suite.Verifier
	Signer         suite.Signer
	CompactedProof bool
	jsonldProcess  *jsonld.Processor
}

func NewBBSSuite(ver *BBSG2SignatureVerifier, sigr *BBSSigSigner, compated bool) *BBSSuite {
	return &BBSSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
		jsonldProcess:  jsonld.NewProcessor(rdfDataSetAlg),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSSuite) GetCanonicalDocument(doc interface{}) ([]byte, error) {
	docMap := make(map[string]interface{})
	b, _ := json.Marshal(doc)
	json.Unmarshal(b, &docMap)
	return bbss.jsonldProcess.GetCanonicalDocument(docMap)
}

// GetDigest returns document digest
func (bbss *BBSSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSSuite) Alg() string {
	return SignatureType
}

func (bbss *BBSSuite) Sign(docByte []byte) ([]byte, error) {

	return bbss.Signer.Sign(splitMessageIntoLines(string(docByte), true))
}

// Verify will verify signature against public key
func (bbss *BBSSuite) Verify(doc, pubkeyBytes, signature []byte) error {
	return bbss.Verifier.Verify(pubkeyBytes, doc, signature)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSSuite) Accept(signatureType string) bool {
	return signatureType == SignatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSSuite) CompactProof() bool {
	return bbss.CompactedProof
}
