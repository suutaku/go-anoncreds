package builder

import (
	"fmt"

	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

const defaultProofPurpose = "assertionMethod"

type VCBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	credential     *credential.Credential
	processorOpts  []processor.ProcessorOpts
}

func NewVCBuilder(cred *credential.Credential, opts ...processor.ProcessorOpts) *VCBuilder {
	return &VCBuilder{
		signatureSuite: make(map[string]suite.SignatureSuite),
		credential:     cred,
		processorOpts:  opts,
	}
}

func (builder *VCBuilder) AddSuite(s suite.SignatureSuite) {
	builder.signatureSuite[s.Alg()] = s
}

func (builder *VCBuilder) AddLinkedDataProof(lcon *proof.LinkedDataProofContext) (*credential.Credential, error) {
	// get signature suit
	suit := builder.signatureSuite[lcon.SignatureType]
	if suit == nil {
		return nil, fmt.Errorf("cannot get signature suite with type: %s", lcon.SignatureType)
	}
	sigedDoc, err := suit.AddLinkedDataProof(lcon, builder.credential)
	if err != nil {
		return nil, err
	}
	builder.credential = sigedDoc
	return sigedDoc, nil
}

func (builder *VCBuilder) Verify(resolver *suite.PublicKeyResolver, nonce []byte) error {
	if builder.credential == nil {
		return fmt.Errorf("credential was empty")
	}
	if builder.credential.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs, err := credential.GetProofs(builder.credential.Proof)
	if err != nil {
		return err
	}
	for _, pm := range proofs {
		p := proof.NewProofFromMap(pm)
		suit := builder.signatureSuite[pm["type"].(string)]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", pm["type"].(string))
		}
		err = suit.Verify(builder.credential, p, resolver, nonce)
		if err != nil {
			return err
		}
	}
	return nil

}
func (builder *VCBuilder) GenerateBBSSelectiveDisclosure(revealDoc *credential.Credential, pubKey *suite.PublicKey, nonce []byte, opts ...processor.ProcessorOpts) (*credential.Credential, error) {
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

	return s.SelectiveDisclosure(builder.credential, revealDoc, pubKey, nonce, opts...)

}

func (builder *VCBuilder) PreBlindSign(secDoc *credential.Credential, nonce []byte, opts ...processor.ProcessorOpts) (*bbs.BlindSignatureContext, error) {
	if builder.credential == nil {
		return nil, fmt.Errorf("no credential parsed")
	}
	s := builder.signatureSuite[bbsblssignature2020.SignatureType]
	if s == nil {
		return nil, fmt.Errorf("expected at least one signature suit present")
	}
	return s.(*bbsblssignature2020.BBSSuite).PreBlindSign(builder.credential, secDoc, nonce, opts...)
}

func (builder *VCBuilder) BlindSign(ctxBytes []byte, revealedIdxs []int, msgCount int, pubBytes, nonce []byte) (*bbs.BlindSignature, error) {
	if builder.credential == nil {
		return nil, fmt.Errorf("no credential parsed")
	}
	s := builder.signatureSuite[bbsblssignature2020.SignatureType]
	if s == nil {
		return nil, fmt.Errorf("expected at least one signature suit present")
	}
	return s.(*bbsblssignature2020.BBSSuite).BlindSign(ctxBytes, builder.credential.ToMap(), revealedIdxs, msgCount, pubBytes, nonce)
}

func (builder *VCBuilder) CompleteSignture(lcon *proof.LinkedDataProofContext, blindSig *bbs.BlindSignature) (*credential.Credential, error) {
	// get signature suit
	suit, ok := builder.signatureSuite[lcon.SignatureType].(*bbsblssignature2020.BBSSuite)
	if !ok || suit == nil {
		return nil, fmt.Errorf("cannot get signature suite with type: %s", lcon.SignatureType)
	}
	sigedDoc, err := suit.CompleteSignture(lcon, builder.credential, blindSig, suit.BlindingFactor())
	if err != nil {
		return nil, err
	}
	builder.credential = sigedDoc
	return sigedDoc, nil
}
