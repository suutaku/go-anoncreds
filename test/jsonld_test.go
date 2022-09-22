package test

import (
	"encoding/json"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/suutaku/go-anoncreds/pkg/vc"
)

func TestJsonLD(t *testing.T) {
	cred := vc.NewCredential()
	cred.Parse([]byte(vcDoc))
	processor := ld.NewJsonLdProcessor()
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = "URDNA2015"
	ldOptions.Format = "application/n-quads"
	ldOptions.ProduceGeneralizedRdf = true
	simple := make(map[string]interface{})
	b, _ := json.Marshal(cred)
	json.Unmarshal(b, &simple)
	// credMap := structs.Map(cred)
	t.Logf("%#v\n", simple)
	iface, err := processor.Normalize(simple, ldOptions)
	if err != nil {
		panic(err)
	}
	t.Logf("%#v\n", iface)
}
