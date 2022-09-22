package bbsblssignature2020

import (
	"fmt"

	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSSigner struct {
	pk   *bbs.PrivateKey
	algo *bbs.Bbs
}

func NewBBSSigner(pk *bbs.PrivateKey) *BBSSigner {
	return &BBSSigner{
		pk:   pk,
		algo: bbs.NewBbs(),
	}
}

func (sig *BBSSigner) PrivateKey() *bbs.PrivateKey {
	return sig.pk
}

func (sig *BBSSigner) PublicKey() *bbs.PublicKey {
	if sig.pk == nil {
		return nil
	}
	return sig.pk.PublicKey()
}

func (sig *BBSSigner) Sign(msg [][]byte) ([]byte, error) {
	if sig.pk == nil {
		return nil, fmt.Errorf("private key was empty")
	}
	return sig.algo.SignWithKey(msg, sig.pk)
}

func (sig *BBSSigner) Alg() string {
	return "BbsBlsSignature2020"
}
