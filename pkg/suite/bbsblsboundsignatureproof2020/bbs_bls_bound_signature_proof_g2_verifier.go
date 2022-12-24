package bbsblsboundsignatureproof2020

import (
	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSBG2SignatureProofVerifier struct {
	algo  *bbs.Bbs
	nonce []byte
	// resolver *suite.PublickKeyResolver
}

func NewBBSG2SignatureProofVerifier(nonce []byte) *BBSBG2SignatureProofVerifier {
	return &BBSBG2SignatureProofVerifier{
		algo:  bbs.NewBbs(),
		nonce: nonce,
	}
}

func (verifier *BBSBG2SignatureProofVerifier) Verify(pubkeyBytes, doc, proof []byte) error {

	return verifier.algo.VerifyProof(tools.SplitMessageIntoLines(string(doc), true), proof, verifier.nonce, pubkeyBytes)
}
