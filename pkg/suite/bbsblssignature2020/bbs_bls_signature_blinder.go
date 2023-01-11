package bbsblssignature2020

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type Blinder struct {
	revealedIdxs []int
	msgCount     int
	blindFactor  *bbs.SignatureBliding
}

func NewBlinder() *Blinder {
	return &Blinder{}
}
func (bld *Blinder) CreateNonce() *bbs.ProofNonce {
	return bbs.NewProofNonce()
}

func (bld *Blinder) CreateContext(secretMsgs map[int][]byte, generator *bbs.PublicKeyWithGenerators, nonce *bbs.ProofNonce) (*bbs.BlindSignatureContext, error) {
	ctx, factor, err := bbs.NewBlindSignatureContext(secretMsgs, generator, nonce)
	bld.blindFactor = factor
	return ctx, err
}

func (bld *Blinder) MessageCount() int {
	return bld.msgCount
}
