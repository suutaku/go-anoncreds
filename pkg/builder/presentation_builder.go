package builder

import (
	"fmt"

	resolver "github.com/suutaku/go-anoncreds/pkg/key-resolver"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/presentation"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

type PRBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	pr             *presentation.Presentation
	processorOpts  []processor.ProcessorOpts
}

func NewPRBuilder(pr *presentation.Presentation, opts ...processor.ProcessorOpts) *PRBuilder {
	return &PRBuilder{
		signatureSuite: make(map[string]suite.SignatureSuite),
		pr:             pr,
		processorOpts:  opts,
	}
}

func (builder *PRBuilder) AddSuite(s suite.SignatureSuite) {
	builder.signatureSuite[s.Alg()] = s
}

func (builder *PRBuilder) AddLinkedDataProof(lcon *proof.LinkedDataProofContext, opts ...processor.ProcessorOpts) (interface{}, error) {
	// get signature suit
	suit := builder.signatureSuite[lcon.SignatureType]
	if suit == nil {
		return nil, fmt.Errorf("cannot get signature suite with type: %s", lcon.SignatureType)
	}
	builder.pr.Proof = make([]interface{}, len(builder.pr.Credential))
	for k, v := range builder.pr.Credential {
		sigedDoc, err := suit.AddLinkedDataProof(lcon, &v, opts...)
		if err != nil {
			return nil, err
		}
		builder.pr.Proof[k] = sigedDoc.Proof
	}

	return builder.pr, nil
}

func (builder *PRBuilder) Verify(resolver resolver.PublicKeyResolver, opts ...processor.ProcessorOpts) error {
	if builder.pr == nil {
		return fmt.Errorf("credential was empty")
	}
	if builder.pr.Proof == nil || len(builder.pr.Proof) == 0 {
		return fmt.Errorf("proof was empty")
	}
	for i, val := range builder.pr.Proof {
		proofs, err := credential.GetProofs(val)
		if err != nil {
			return err
		}
		for _, pm := range proofs {
			p := proof.NewProofFromMap(pm)

			suit := builder.signatureSuite[pm["type"].(string)]
			if suit == nil {
				return fmt.Errorf("cannot get singanture suite for type: %s", pm["type"].(string))
			}
			err = suit.Verify(&builder.pr.Credential[i], p, resolver, p.Nonce, opts...)
			if err != nil {
				return err
			}
		}
	}
	return nil

}
