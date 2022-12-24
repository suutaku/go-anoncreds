package bbsblsboundsignature2020

import (
	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSBG2SignatureVerifier struct {
	algo *bbs.Bbs
	// resolver *suite.PublickKeyResolver
}

func NewBBSG2SignatureVerifier() *BBSBG2SignatureVerifier {
	return &BBSBG2SignatureVerifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *BBSBG2SignatureVerifier) Verify(pubKeyBytes, doc, signature []byte) error {
	return verifier.algo.Verify(tools.SplitMessageIntoLines(string(doc), false), signature, pubKeyBytes)
}
