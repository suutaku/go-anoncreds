package builder

import (
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/proof"
)

const (
	partsNumber   = 3
	headerPart    = 0
	signaturePart = 2
)

const (
	jsonldContext        = "@context"
	jsonldJWS            = "jws"
	jsonldProofValue     = "proofValue"
	ed25519Signature2020 = "Ed25519Signature2020"
)

func (builder *VCBuilder) prepareCanonicalProofOptions(s suite.SignatureSuite, pOtions *proof.Proof) ([]byte, error) {
	docCpy := pOtions.ToMapWithoutProofValue()
	delete(docCpy, "proofValue")
	delete(docCpy, "jws")
	delete(docCpy, "id")
	delete(docCpy, "nonce")
	if s.CompactProof() {
		docCompacted, err := builder.getCompactedWithSecuritySchema()
		if err != nil {
			return nil, err
		}
		delete(docCompacted, "proofValue")
		delete(docCompacted, "jws")
		delete(docCompacted, "id")
		delete(docCompacted, "nonce")
		docCpy = docCompacted
	}

	return s.GetCanonicalDocument(docCpy, builder.processorOpts...)
}

func (builder *VCBuilder) prepareCanonicalProofOptionsJWS(s suite.SignatureSuite, pOtions *proof.Proof) ([]byte, error) {
	pCpy := pOtions.ToMapWithoutProofValue()
	return s.GetCanonicalDocument(pCpy, builder.processorOpts...)
}

func (builder *VCBuilder) prepareCanonicalDocument(s suite.SignatureSuite) ([]byte, error) {
	docCpy := builder.credential.ToMapWithoutProof()
	return s.GetCanonicalDocument(docCpy, builder.processorOpts...)
}

func (builder *VCBuilder) prepareCanonicalDocumentJWS(s suite.SignatureSuite) ([]byte, error) {
	docCpy := builder.credential.ToMapWithoutProof()
	if s.CompactProof() {

		docCompacted, err := builder.getCompactedWithSecuritySchema()
		if err != nil {
			return nil, err
		}

		docCpy = docCompacted
	}
	return s.GetCanonicalDocument(docCpy, builder.processorOpts...)
}

func (builder *VCBuilder) CreateVerifyJWS(s suite.SignatureSuite, p *proof.Proof) ([]byte, error) {
	canonicalProofOptions, err := builder.prepareCanonicalProofOptionsJWS(s, p)
	if err != nil {
		return nil, err
	}
	proofOptionsDigest := s.GetDigest(canonicalProofOptions)
	canonicalDoc, err := builder.prepareCanonicalDocumentJWS(s)
	if err != nil {
		return nil, err
	}
	docDigest := s.GetDigest(canonicalDoc)
	verifyData := append(proofOptionsDigest, docDigest...)
	builder.jwt.Parse(p.JWS)
	return append([]byte(builder.jwt.Header()+"."), verifyData...), nil
}
