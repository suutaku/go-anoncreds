package bbsblssignatureproof2020

import (
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSSigProofSigner struct {
	bbsblssignature2020.BBSSigSigner
}

func NewBBSSigProofSigner(pk *bbs.PrivateKey) *BBSSigProofSigner {
	return &BBSSigProofSigner{
		BBSSigSigner: *bbsblssignature2020.NewBBSSigner(pk),
	}
}

func (bbsp *BBSSigProofSigner) DeriveProof(message [][]byte, sig, nonce, pubkey []byte, indexes []int) ([]byte, error) {
	return bbsp.BBSSigSigner.BBS().DeriveProof(message, sig, nonce, pubkey, indexes)
}
