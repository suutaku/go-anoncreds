package vc

import (
	"time"
)

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext struct {
	SignatureType           string    // required
	SignatureRepresentation int       // required
	Created                 time.Time // optional
	VerificationMethod      string    // optional
	Challenge               string    // optional
	Domain                  string    // optional
	Purpose                 string    // optional
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{}
}

func mapContext(context *LinkedDataProofContext) *Context {
	return &Context{
		SignatureType:           context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Created:                 context.Created,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		Domain:                  context.Domain,
		Purpose:                 context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
}
