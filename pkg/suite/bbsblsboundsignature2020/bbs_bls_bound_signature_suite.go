package bbsblsboundsignature2020

import (
	"encoding/json"

	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/processor"
)

const (
	SignatureType = "BbsBlsBoundSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type BBSBSuite struct {
	Verifier       suite.Verifier
	Signer         suite.Signer
	CompactedProof bool
	jsonldProcess  *processor.JsonLDProcessor
}

func NewBBSSuite(ver *BBSBG2SignatureVerifier, sigr *BBSBSigSigner, compated bool) *BBSBSuite {
	return &BBSBSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
		jsonldProcess:  processor.NewJsonLDProcessor(),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSBSuite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
	docMap := make(map[string]interface{})
	b, _ := json.Marshal(doc)
	json.Unmarshal(b, &docMap)
	return bbss.jsonldProcess.GetCanonicalDocument(docMap)
}

// GetDigest returns document digest
func (bbss *BBSBSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSBSuite) Alg() string {
	return SignatureType
}

func (bbss *BBSBSuite) Sign(docByte []byte) ([]byte, error) {
	return bbss.Signer.Sign(tools.SplitMessageIntoLines(string(docByte), false))
}

// Verify will verify signature against public key
func (bbss *BBSBSuite) Verify(doc, pubkeyBytes, signature []byte) error {
	return bbss.Verifier.Verify(pubkeyBytes, doc, signature)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSBSuite) Accept(signatureType string) bool {
	return signatureType == SignatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSBSuite) CompactProof() bool {
	return bbss.CompactedProof
}
