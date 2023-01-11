package bbsblssignatureproof2020

import (
	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSG2SignatureProofVerifier struct {
	algo *bbs.Bbs

	// resolver *suite.PublickKeyResolver
}

func NewBBSG2SignatureProofVerifier() *BBSG2SignatureProofVerifier {
	return &BBSG2SignatureProofVerifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *BBSG2SignatureProofVerifier) Verify(pubkeyBytes, doc, proof, nonce []byte) error {

	return verifier.algo.VerifyProof(tools.SplitMessageIntoLines(string(doc), true), proof, nonce, pubkeyBytes)
}
