package vc

import (
	"errors"
	"fmt"
	"time"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
)

const defaultProofPurpose = "assertionMethod"

// Context holds signing options and private key.
type Context struct {
	SignatureType           string        // required
	Creator                 string        // required
	SignatureRepresentation int           // optional
	Created                 time.Time     // optional
	Domain                  string        // optional
	Nonce                   []byte        // optional
	VerificationMethod      string        // optional
	Challenge               string        // optional
	Purpose                 string        // optional
	CapabilityChain         []interface{} // optional
}

type VCBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	credential     *Credential
}

func NewVCBuilder(cred *Credential) *VCBuilder {
	return &VCBuilder{
		signatureSuite: make(map[string]suite.SignatureSuite),
		credential:     cred,
	}
}

func (builder *VCBuilder) AddSuite(s suite.SignatureSuite) {
	builder.signatureSuite[s.Alg()] = s
}

func (builder *VCBuilder) build(context *Context) error {
	// validation of context
	if context.SignatureType == "" {
		return fmt.Errorf("signature type is missing")
	}
	if context.Created.IsZero() {
		context.Created = time.Now()
	}
	if context.Purpose == "" {
		context.Purpose = defaultProofPurpose
	}

	// get signature suit
	suit := builder.signatureSuite[context.SignatureType]
	if suit == nil {
		return fmt.Errorf("cannot get signature suite with type: %s", context.SignatureType)
	}

	// construct proof
	p := &Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created.String(),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if context.SignatureRepresentation == SignatureJWS {
		p.JWS = createDetachedJWTHeader(suit.Alg() + "..")
	}

	message, err := createVerifyData(suit, builder.credential.ToMap(), p)
	if err != nil {
		return err
	}
	sig, err := suit.Sign(message)
	if err != nil {
		return err
	}
	builder.applySignatureValue(context, p, sig)
	return AddProof(builder.credential, p)
}

func (builder *VCBuilder) Verify(resolver *suite.PublicKeyResolver) error {
	if builder.credential == nil {
		return fmt.Errorf("credential was empty")
	}
	if builder.credential.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs, err := getProofs(builder.credential.Proof)
	if err != nil {
		return err
	}
	for _, pm := range proofs {
		p := NewProofFromMap(pm)
		suit := builder.signatureSuite[pm["type"].(string)]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", pm["type"].(string))
		}
		// get verify data
		message, err := createVerifyData(suit, builder.credential.ToMap(), p)
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

func (builder *VCBuilder) AddLinkedDataProof(lcon *LinkedDataProofContext) error {
	context := mapContext(lcon)
	return builder.build(context)
}

func (builder *VCBuilder) GenerateBBSSelectiveDisclosure(revealDoc *Credential, pubKey *suite.PublicKey, nonce []byte, opts ...jsonld.ProcessorOpts) (*Credential, error) {
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

	docWithoutProof, rawProofs, err := prepareDocAndProof(builder.credential.ToMap(), opts...)
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}

	blsSignatures, err := getBlsProofs(rawProofs)
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}

	if len(blsSignatures) == 0 {
		return nil, errors.New("no BbsBlsSignature2020 proof present")
	}

	docVerData, pErr := buildDocVerificationData(docWithoutProof, revealDoc.ToMap(), opts...)
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}

	proofs := make([]map[string]interface{}, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := buildVerificationData(blsSignature, docVerData, opts...)
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
	ret := NewCredential()
	ret.FromMap(revealDocumentResult)
	return ret, nil
}
