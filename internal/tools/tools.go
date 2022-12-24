package tools

import (
	"fmt"
	"strings"
)

func SplitMessageIntoLinesStr(msg string, transformBlankNodes bool) []string {
	rows := strings.Split(msg, "\n")

	msgs := make([]string, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		if transformBlankNodes {
			row = TransformFromBlankNode(row)
		}

		msgs = append(msgs, row)
	}

	return msgs
}

func SplitMessageIntoLines(msg string, transformBlankNodes bool) [][]byte {
	rows := strings.Split(msg, "\n")

	msgs := make([][]byte, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		if transformBlankNodes {
			row = TransformFromBlankNode(row)
		}

		msgs = append(msgs, []byte(row))
	}

	return msgs
}

func TransformFromBlankNode(row string) string {
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
