package bbsblssignatureproof2020

import (
	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSG2SignatureProofVerifier struct {
	algo  *bbs.Bbs
	nonce []byte
	// resolver *suite.PublickKeyResolver
}

func NewBBSG2SignatureProofVerifier(nonce []byte) *BBSG2SignatureProofVerifier {
	return &BBSG2SignatureProofVerifier{
		algo:  bbs.NewBbs(),
		nonce: nonce,
	}
}

func (verifier *BBSG2SignatureProofVerifier) Verify(pubkeyBytes, doc, proof []byte) error {

	return verifier.algo.VerifyProof(tools.SplitMessageIntoLines(string(doc), true), proof, verifier.nonce, pubkeyBytes)
}
