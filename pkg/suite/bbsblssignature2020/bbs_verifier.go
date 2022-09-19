package bbsblssignature2020

import (
	"crypto"
	"fmt"

	"github.com/suutaku/go-anoncreds/pkg/credential"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSVerifier struct {
	algo     *bbs.Bbs
	resolver *suite.PublickKeyResolver
}

func NewBBSVerifier() *BBSVerifier {
	return &BBSVerifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *BBSVerifier) Verify(pubKey crypto.PublicKey, doc, signature []byte) error {
	keyBytes, err := pubKey.(*bbs.PublicKey).Marshal()
	if err != nil {
		return err
	}
	return verifier.algo.Verify([][]byte{doc}, signature, keyBytes)
}

func (verifier *BBSVerifier) VerifyProof(cred *credential.Credential) error {
	if cred.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs := make([]*credential.Proof, 0)

	switch x := cred.Proof.(type) {
	case []interface{}:
		for _, v := range x {
			proofs = append(proofs, v.(*credential.Proof))
		}
	case []*credential.Proof:
		for _, v := range x {
			proofs = append(proofs, v)
		}
	case *credential.Proof:
		proofs = append(proofs, x)
	}
	for _, p := range proofs {
		pid, err := p.PublicKeyId()
		if err != nil {
			return err
		}
		pbk := verifier.resolver.Resolve(pid)
		if pbk == nil {
			return fmt.Errorf("cannot resolve public key")
		}
		// get verify data
		message, err := credential.CreateVerifyData(NewBBSSuite(nil, nil, false), cred, p)
		if err != nil {
			return err
		}
		// get verify value
		signature, err := getProofVerifyValue(p)
		if err != nil {
			return err
		}
		err = verifier.Verify(pbk, message, signature)
		if err != nil {
			return err
		}

	}
	return nil
}

func getProofVerifyValue(p *credential.Proof) ([]byte, error) {

	if p.SignatureRepresentation == 0 {
		return p.ProofValue, nil
	} else if p.SignatureRepresentation == 1 {
		return credential.GetJWTSignature(p.JWS)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}
