package bbsblssignature2020

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/suutaku/go-anoncreds/pkg/credential"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSVerifier struct {
	algo *bbs.Bbs
	// resolver *suite.PublickKeyResolver
}

func NewBBSVerifier() *BBSVerifier {
	return &BBSVerifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *BBSVerifier) Verify(pubKey crypto.PublicKey, doc, signature []byte) error {
	keyBytes := pubKey.(*suite.PublicKey).Value
	return verifier.algo.Verify([][]byte{doc}, signature, keyBytes)
}

func (verifier *BBSVerifier) VerifyProof(cred *credential.Credential, resolver *suite.PublicKeyResolver) error {
	if cred.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs := make([]*credential.Proof, 0)

	switch x := cred.Proof.(type) {
	case []interface{}:
		for _, v := range x {
			tmp := credential.Proof{}
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
		tmp := credential.Proof{}
		cfg := &mapstructure.DecoderConfig{
			Metadata: nil,
			Result:   &tmp,
			TagName:  "json",
		}
		decoder, _ := mapstructure.NewDecoder(cfg)
		decoder.Decode(x)
		proofs = append(proofs, &tmp)
	case []*credential.Proof:
		for _, v := range x {
			proofs = append(proofs, v)
		}
	case *credential.Proof:
		proofs = append(proofs, x)
	case credential.Proof:
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
		// get verify data
		message, err := credential.CreateVerifyData(cred, p)
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

		return decodeBase64(p.ProofValue)
	} else if p.SignatureRepresentation == 1 {
		return credential.GetJWTSignature(p.JWS)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, errors.New("unsupported encoding")
}
