package vc

import (
	"encoding/base64"
	"fmt"
)

var (
	rdfDataSetAlg = "URDNA2015"
)

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, fmt.Errorf("unsupported encoding")
}
