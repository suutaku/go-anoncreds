package bbsblssignature2020

import (
	"crypto/sha256"

	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSSigner struct {
	pk    *bbs.PrivateKey
	suite *bbs.Bbs
}

func NewBBSSigner(pk *bbs.PrivateKey) *BBSSigner {
	ret := &BBSSigner{}
	if pk == nil {
		_, npk, err := bbs.GenerateKeyPair(sha256.New, nil)
		if err != nil {
			panic(err)
		}
		ret.pk = npk
	} else {
		ret.pk = pk
	}
	ret.suite = bbs.NewBbs()
	return ret
}

func (sig *BBSSigner) PrivateKey() *bbs.PrivateKey {
	return sig.pk
}

func (sig *BBSSigner) PublicKey() *bbs.PublicKey {
	return sig.pk.PublicKey()
}

func (sig *BBSSigner) Sign(msg [][]byte) ([]byte, error) {
	return sig.suite.SignWithKey(msg, sig.pk)
}

func (sig *BBSSigner) Alg() string {
	return "BbsBlsSignature2020"
}
