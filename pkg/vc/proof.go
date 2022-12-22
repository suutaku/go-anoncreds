package vc

import (
	"encoding/json"
	"fmt"
)

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://w3id.org/security/jws/v1"
	bbsBlsSignature2020    = "BbsBlsSignature2020"
)

const (
	SignatureProofValue int = iota
	SignatureJWS
)

// Proof is cryptographic proof of the integrity of the DID Document.
type Proof struct {
	Context                 interface{} `json:"@context,omitempty"`
	Type                    string      `json:"type,omitempty"`
	Created                 string      `json:"created,omitempty"`
	Creator                 string      `json:"creator,omitempty"`
	VerificationMethod      string      `json:"verificationMethod,omitempty"`
	ProofValue              string      `json:"proofValue,omitempty"`
	JWS                     string      `json:"jws,omitempty"`
	ProofPurpose            string      `json:"proofPurpose,omitempty"`
	Domain                  string      `json:"domain,omitempty"`
	Nonce                   []byte      `json:"nonce,omitempty"`
	Challenge               string      `json:"challenge,omitempty"`
	SignatureRepresentation int         `json:"-"`
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{} `json:"capabilityChain,omitempty"`
}

func NewProof(ptype string) *Proof {
	return &Proof{
		Type: ptype,
	}
}

func NewProofFromMap(data map[string]interface{}) *Proof {
	ret := &Proof{}
	b, _ := json.Marshal(data)
	json.Unmarshal(b, ret)
	return ret
}

func (p *Proof) Parse(raw []byte) error {
	err := json.Unmarshal(raw, p)
	if err != nil {
		return err
	}
	if len(p.ProofValue) == 0 && p.JWS == "" {
		return fmt.Errorf("invlaid raw data")
	}
	return err
}

func (p *Proof) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(b, &ret)
	if err != nil {
		return nil
	}
	return ret
}

func (p *Proof) Copy() *Proof {
	return &Proof{
		Context:                 p.Context,
		Type:                    p.Type,
		Created:                 p.Created,
		Creator:                 p.Creator,
		VerificationMethod:      p.VerificationMethod,
		ProofValue:              p.ProofValue,
		JWS:                     p.JWS,
		ProofPurpose:            p.ProofPurpose,
		Domain:                  p.Domain,
		Nonce:                   p.Nonce,
		Challenge:               p.Challenge,
		SignatureRepresentation: p.SignatureRepresentation,
		CapabilityChain:         p.CapabilityChain,
	}
}

func (p *Proof) CopyWithoutSecuritySchemas() *Proof {
	copied := p.Copy()
	copied.ProofValue = ""
	copied.JWS = ""
	copied.Nonce = nil
	return copied
}

func (p *Proof) Bytes() []byte {
	b, _ := json.Marshal(p)
	return b
}

func (p *Proof) PublicKeyId() (string, error) {
	if p.VerificationMethod != "" {
		return p.VerificationMethod, nil
	}

	if p.Creator != "" {
		return p.Creator, nil
	}

	return "", fmt.Errorf("no public key id")
}
