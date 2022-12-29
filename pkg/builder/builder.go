package builder

import (
	"encoding/base64"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

const defaultProofPurpose = "assertionMethod"

type VCBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	credential     *credential.Credential
	processor      *processor.JsonLDProcessor
	jwt            *proof.Jwt
}

func NewVCBuilder(cred *credential.Credential) *VCBuilder {
	return &VCBuilder{
		signatureSuite: make(map[string]suite.SignatureSuite),
		credential:     cred,
		processor:      processor.NewJsonLDProcessor(),
	}
}

func (builder *VCBuilder) AddSuite(s suite.SignatureSuite) {
	builder.signatureSuite[s.Alg()] = s
}

func (builder *VCBuilder) AddLinkedDataProof(lcon *proof.LinkedDataProofContext) error {
	return builder.build(lcon.ToContext())
}

func (builder *VCBuilder) build(context *proof.Context) error {
	// validation of context
	if err := context.Validate(); err != nil {
		return err
	}

	// get signature suit
	suit := builder.signatureSuite[context.SignatureType]
	if suit == nil {
		return fmt.Errorf("cannot get signature suite with type: %s", context.SignatureType)
	}

	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created,
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}

	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = builder.jwt.NewHeader(suit.Alg() + "..")
	}
	message, err := builder.createVerifyData(suit, p)
	if err != nil {
		return err
	}
	sig, err := suit.Sign(message)
	if err != nil {
		return err
	}
	logrus.Warn("debug ", base64.RawURLEncoding.EncodeToString(sig))
	p.ApplySignatureValue(context, sig)

	return builder.credential.AddProof(p)
}

func (builder *VCBuilder) createVerifyData(s suite.SignatureSuite, p *proof.Proof) ([]byte, error) {
	switch p.SignatureRepresentation {
	case proof.SignatureProofValue:
		return builder.createVerifyHash(s, p)
	case proof.SignatureJWS:
		return builder.CreateVerifyJWS(s, p)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

func (builder *VCBuilder) createVerifyHash(s suite.SignatureSuite, p *proof.Proof) ([]byte, error) {

	if p.Context == nil {
		p.Context = builder.credential.Context
	}
	canonicalProofOptions, err := builder.prepareCanonicalProofOptions(s, p)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := s.GetDigest(canonicalProofOptions)

	canonicalDoc, err := builder.prepareCanonicalDocument(s)
	if err != nil {
		return nil, err
	}

	docDigest := s.GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

func (builder *VCBuilder) Verify(resolver *suite.PublicKeyResolver) error {
	if builder.credential == nil {
		return fmt.Errorf("credential was empty")
	}
	if builder.credential.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs, err := builder.credential.GetProofs()
	if err != nil {
		return err
	}
	for _, pm := range proofs {
		p := proof.NewProofFromMap(pm)
		suit := builder.signatureSuite[pm["type"].(string)]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", pm["type"].(string))
		}
		// get verify data
		message, err := builder.createVerifyData(suit, p)
		if err != nil {
			return err
		}
		pubKeyValue, signature, err := getPublicKeyAndSignature(pm, resolver)
		if err != nil {
			return err
		}
		err = suit.Verify(message, pubKeyValue, signature)
		if err != nil {
			return err
		}
	}
	return nil

}
func (builder *VCBuilder) GenerateBBSSelectiveDisclosure(revealDoc *credential.Credential, pubKey *suite.PublicKey, nonce []byte) (*credential.Credential, error) {
	if builder.credential == nil {
		return nil, fmt.Errorf("no credential parsed")
	}
	if builder.credential.Proof == nil {
		return nil, fmt.Errorf("expected at least one proof present")
	}
	s := builder.signatureSuite[bbsblssignatureproof2020.SignatureProofType]
	if s == nil {
		return nil, fmt.Errorf("expected at least one signature suit present")
	}

	docWithoutProof, err := builder.getCompactedWithSecuritySchema()
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}

	blsSignatures, err := builder.credential.GetBLSProofs()
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}

	if len(blsSignatures) == 0 {
		return nil, fmt.Errorf("no BbsBlsSignature2020 proof present")
	}

	docVerData, pErr := builder.buildDocVerificationData(docWithoutProof, revealDoc.ToMap())
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}

	proofs := make([]map[string]interface{}, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := builder.buildVerificationData(blsSignature, docVerData)
		if dErr != nil {
			return nil, fmt.Errorf("build verification data: %w", dErr)
		}
		resolver := suite.NewPublicKeyResolver(pubKey, nil)
		derivedProof, dErr := generateSignatureProof(blsSignature, resolver, nonce, verData, s)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.revealDocumentResult
	revealDocumentResult["proof"] = proofs
	ret := credential.NewCredential()
	ret.FromMap(revealDocumentResult)
	return ret, nil

}
