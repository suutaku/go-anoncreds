package credential

import (
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

var (
	rdfDataSetAlg = "URDNA2015"
)

// GetCanonicalDocument will return normalized/canonical version of the document
func GetCanonicalDocument(doc interface{}) ([]byte, error) {
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = rdfDataSetAlg
	ldOptions.Format = "application/n-quads"
	ldOptions.ProduceGeneralizedRdf = true
	processor := ld.NewJsonLdProcessor()
	docMap := make(map[string]interface{})
	b, _ := json.Marshal(doc)
	json.Unmarshal(b, &docMap)
	view, err := processor.Normalize(docMap, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	return []byte(result), nil
}

// GetDigest returns document digest
func GetDigest(doc []byte) []byte {
	return doc
}
