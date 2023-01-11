package bbsblssignature2020

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type Blinder struct {
}

func NewBlinder() *Blinder {
	return &Blinder{}
}
func (bld *Blinder) CreateNonce() *bbs.ProofNonce {
	return bbs.NewProofNonce()
}

func (bld *Blinder) CreateContext(secretMsgs map[int][]byte, generator *bbs.PublicKeyWithGenerators, nonce *bbs.ProofNonce) (*bbs.BlindSignatureContext, *bbs.SignatureBliding, error) {
	return bbs.NewBlindSignatureContext(secretMsgs, generator, nonce)
}
