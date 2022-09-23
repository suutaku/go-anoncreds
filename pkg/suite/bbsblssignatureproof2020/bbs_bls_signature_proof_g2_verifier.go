package bbsblssignatureproof2020

import (
	"fmt"
	"strings"

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

func (verifier *BBSG2SignatureProofVerifier) Verify(pubkeyBytes, doc, signature []byte) error {

	return verifier.algo.VerifyProof(splitMessageIntoLines(string(doc), true), signature, verifier.nonce, pubkeyBytes)
}

func splitMessageIntoLines(msg string, transformBlankNodes bool) [][]byte {
	rows := strings.Split(msg, "\n")

	msgs := make([][]byte, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		if transformBlankNodes {
			row = transformFromBlankNode(row)
		}

		msgs = append(msgs, []byte(row))
	}

	return msgs
}

func transformFromBlankNode(row string) string {
	// transform from "urn:bnid:_:c14n0" to "_:c14n0"
	const (
		emptyNodePlaceholder = "<urn:bnid:_:c14n"
		emptyNodePrefixLen   = 10
	)

	prefixIndex := strings.Index(row, emptyNodePlaceholder)
	if prefixIndex < 0 {
		return row
	}

	sepIndex := strings.Index(row[prefixIndex:], ">")
	if sepIndex < 0 {
		return row
	}

	sepIndex += prefixIndex

	prefix := row[:prefixIndex]
	blankNode := row[prefixIndex+emptyNodePrefixLen : sepIndex]
	suffix := row[sepIndex+1:]

	return fmt.Sprintf("%s%s%s", prefix, blankNode, suffix)
}
