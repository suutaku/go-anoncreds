package bbsblssignature2020

import (
	"fmt"

	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSSigSigner struct {
	pk   *bbs.PrivateKey
	algo *bbs.Bbs
}

func NewBBSSigner(pk *bbs.PrivateKey) *BBSSigSigner {
	return &BBSSigSigner{
		pk:   pk,
		algo: bbs.NewBbs(),
	}
}

func (sig *BBSSigSigner) PrivateKey() *bbs.PrivateKey {
	return sig.pk
}

func (sig *BBSSigSigner) PublicKey() *bbs.PublicKey {
	if sig.pk == nil {
		return nil
	}
	return sig.pk.PublicKey()
}

func (sig *BBSSigSigner) Sign(msg [][]byte) ([]byte, error) {
	if sig.pk == nil {
		return nil, fmt.Errorf("private key was empty")
	}
	return sig.algo.SignWithKey(msg, sig.pk)
}

func (sig *BBSSigSigner) Alg() string {
	return "BbsBlsSignature2020"
}
