package bbsblssignature2020

import (
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/processor"
)

const (
	SignatureType = "BbsBlsSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type BBSSuite struct {
	Verifier       suite.Verifier
	Signer         suite.Signer
	CompactedProof bool
	jsonldProcess  *processor.JsonLDProcessor
}

func NewBBSSuite(ver *BBSG2SignatureVerifier, sigr *BBSSigSigner, compated bool) *BBSSuite {
	return &BBSSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
		jsonldProcess:  processor.NewJsonLDProcessor(),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSSuite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {

	return bbss.jsonldProcess.GetCanonicalDocument(doc)

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
