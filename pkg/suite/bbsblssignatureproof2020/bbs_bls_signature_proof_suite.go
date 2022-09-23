package bbsblssignatureproof2020

import (
	"encoding/json"
	"strings"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
)

const (
	SignatureType      = "BbsBlsSignature2020"
	SignatureProofType = "BbsBlsSignatureproof2020"
	rdfDataSetAlg      = "URDNA2015"
)

type BBSPSuite struct {
	Verifier       suite.Verifier
	Signer         suite.Signer
	CompactedProof bool
	jsonldProcess  *jsonld.Processor
}

func NewBBSPSuite(ver *BBSG2SignatureProofVerifier, sigr *BBSSigProofSigner, compated bool) *BBSPSuite {
	return &BBSPSuite{
		Verifier:       ver,
		Signer:         sigr,
		CompactedProof: compated,
		jsonldProcess:  jsonld.NewProcessor(rdfDataSetAlg),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSPSuite) GetCanonicalDocument(doc interface{}) ([]byte, error) {
	docMap := make(map[string]interface{})
	b, _ := json.Marshal(doc)
	json.Unmarshal(b, &docMap)
	if v, ok := docMap["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, SignatureProofType) {
			docType = strings.Replace(docType, SignatureProofType, SignatureType, 1)
			docMap["type"] = docType
		}
	}

	return bbss.jsonldProcess.GetCanonicalDocument(docMap)
}

// GetDigest returns document digest
func (bbss *BBSPSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSPSuite) Alg() string {
	return SignatureProofType
}

func (bbss *BBSPSuite) Sign(docByte []byte) ([]byte, error) {

	return bbss.Signer.Sign(splitMessageIntoLines(string(docByte), true))
}

// Verify will verify signature against public key
func (bbss *BBSPSuite) Verify(doc, pubkeyBytes, signature []byte) error {
	return bbss.Verifier.Verify(pubkeyBytes, doc, signature)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSPSuite) Accept(signatureType string) bool {
	return signatureType == SignatureProofType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSPSuite) CompactProof() bool {
	return bbss.CompactedProof
}

func (bbs *BBSPSuite) SelectiveDisclosure(blsMessages [][]byte, signature, nonce, pubKeyBytes []byte, revIndexes []int) ([]byte, error) {
	return bbs.Signer.(*BBSSigProofSigner).DeriveProof(blsMessages, signature, nonce, pubKeyBytes, revIndexes)
}
