package bbsblssignature2020

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

type BBSG2SignatureVerifier struct {
	algo *bbs.Bbs
	// resolver *suite.PublickKeyResolver
}

func NewBBSG2SignatureVerifier() *BBSG2SignatureVerifier {
	return &BBSG2SignatureVerifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *BBSG2SignatureVerifier) Verify(pubKey crypto.PublicKey, doc, signature []byte) error {
	keyBytes := pubKey.(*suite.PublicKey).Value
	return verifier.algo.Verify(splitMessageIntoLines(string(doc), true), signature, keyBytes)
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
