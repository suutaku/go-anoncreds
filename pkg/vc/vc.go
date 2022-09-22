package vc

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/suutaku/go-anoncreds/pkg/suite"
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
		p.JWS = CreateDetachedJWTHeader(suit.Alg() + "..")
	}

	message, err := CreateVerifyData(suit, builder.credential, p)
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
	proofs := make([]*Proof, 0)

	switch x := builder.credential.Proof.(type) {
	case []interface{}:
		for _, v := range x {
			tmp := Proof{}
			cfg := &mapstructure.DecoderConfig{
				Metadata: nil,
				Result:   &tmp,
				TagName:  "json",
			}
			decoder, _ := mapstructure.NewDecoder(cfg)
			decoder.Decode(v)
			proofs = append(proofs, &tmp)
		}
	case interface{}:
		tmp := Proof{}
		cfg := &mapstructure.DecoderConfig{
			Metadata: nil,
			Result:   &tmp,
			TagName:  "json",
		}
		decoder, _ := mapstructure.NewDecoder(cfg)
		decoder.Decode(x)
		proofs = append(proofs, &tmp)
	case []*Proof:
		for _, v := range x {
			proofs = append(proofs, v)
		}
	case *Proof:
		proofs = append(proofs, x)
	case Proof:
		proofs = append(proofs, &x)
	}
	for _, p := range proofs {
		pid, err := p.PublicKeyId()
		if err != nil {
			return err
		}
		pbk := resolver.Resolve(pid)
		if pbk == nil {
			return fmt.Errorf("cannot resolve public key")
		}
		suit := builder.signatureSuite[p.Type]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", p.Type)
		}
		// get verify data
		message, err := CreateVerifyData(suit, builder.credential, p)
		if err != nil {
			return err
		}
		// get verify value
		signature, err := getProofVerifyValue(p)
		if err != nil {
			return err
		}

		pubKeyValue := pbk.Value
		if p.SignatureRepresentation == SignatureJWS {
			pubKeyValue = pbk.Jwk
		}
		err = suit.Verify(pubKeyValue, message, signature)
		if err != nil {
			return err
		}

	}
	return nil
}

func (vc *VCBuilder) applySignatureValue(context *Context, p *Proof, s []byte) {
	switch context.SignatureRepresentation {
	case SignatureProofValue:
		p.ProofValue = base64.RawURLEncoding.EncodeToString(s)
	case SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

func getProofVerifyValue(p *Proof) ([]byte, error) {

	if p.SignatureRepresentation == 0 {

		return decodeBase64(p.ProofValue)
	} else if p.SignatureRepresentation == 1 {
		return GetJWTSignature(p.JWS)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

func (builder *VCBuilder) AddLinkedDataProof(lcon *LinkedDataProofContext) error {
	context := mapContext(lcon)
	return builder.build(context)
}

func (builder *VCBuilder) GenerateBBSSelectiveDIsclosure(revealDoc map[string]interface{}, pubKey *suite.PublicKey, nonce []byte) (*Credential, error) {
	if builder.credential.Proof == nil {
		return nil, fmt.Errorf("expected at least one proof present")
	}
	return nil, nil
}
