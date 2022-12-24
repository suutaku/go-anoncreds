package bbsblsboundsignatureproof2020

import (
	"strings"

	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/processor"
)

const (
	SignatureType      = "BbsBlsBoundSignature2020"
	SignatureProofType = "BbsBlsBoundSignatureproof2020"
)

type BBSBPSuite struct {
	Verifier        suite.Verifier
	Signer          suite.Signer
	CompactedProof  bool
	jsonldProcessor *processor.JsonLDProcessor
}

func NewBBSPSuite(ver *BBSBG2SignatureProofVerifier, sigr *BBSBSigProofSigner, compated bool) *BBSBPSuite {
	return &BBSBPSuite{
		Verifier:        ver,
		Signer:          sigr,
		CompactedProof:  compated,
		jsonldProcessor: processor.NewJsonLDProcessor(),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSBPSuite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
	if v, ok := doc["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, SignatureProofType) {
			docType = strings.Replace(docType, SignatureProofType, SignatureType, 1)
			doc["type"] = docType
		}
	}

	return bbss.jsonldProcessor.GetCanonicalDocument(doc)
}

// GetDigest returns document digest
func (bbss *BBSBPSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSBPSuite) Alg() string {
	return SignatureProofType
}

func (bbss *BBSBPSuite) Sign(docByte []byte) ([]byte, error) {

	return bbss.Signer.Sign(tools.SplitMessageIntoLines(string(docByte), false))
}

// Verify will verify signature against public key
func (bbss *BBSBPSuite) Verify(doc, pubkeyBytes, proof []byte) error {
	return bbss.Verifier.Verify(pubkeyBytes, doc, proof)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSBPSuite) Accept(signatureType string) bool {
	return signatureType == SignatureProofType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSBPSuite) CompactProof() bool {
	return bbss.CompactedProof
}

func (bbs *BBSBPSuite) SelectiveDisclosure(blsMessages [][]byte, signature, nonce, pubKeyBytes []byte, revIndexes []int) ([]byte, error) {
	return bbs.Signer.(*BBSBSigProofSigner).DeriveProof(blsMessages, signature, nonce, pubKeyBytes, revIndexes)
}
