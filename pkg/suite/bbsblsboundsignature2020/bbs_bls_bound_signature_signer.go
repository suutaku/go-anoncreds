package bbsblsboundsignature2020

import (
	"fmt"

	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSBSigSigner struct {
	pk   *bbs.PrivateKey
	algo *bbs.Bbs
}

func NewBBSBSigner(pk *bbs.PrivateKey) *BBSBSigSigner {
	return &BBSBSigSigner{
		pk:   pk,
		algo: bbs.NewBbs(),
	}
}

func (sig *BBSBSigSigner) BBS() *bbs.Bbs {
	return sig.algo
}

func (sig *BBSBSigSigner) PrivateKey() *bbs.PrivateKey {
	return sig.pk
}

func (sig *BBSBSigSigner) PublicKey() *bbs.PublicKey {
	if sig.pk == nil {
		return nil
	}
	return sig.pk.PublicKey()
}

func (sig *BBSBSigSigner) Sign(msg [][]byte) ([]byte, error) {
	if sig.pk == nil {
		return nil, fmt.Errorf("private key was empty")
	}
	return sig.algo.SignWithKey(msg, sig.pk)
}

func (sig *BBSBSigSigner) Alg() string {
	return SignatureType
}
