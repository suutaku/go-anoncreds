package vc

import (
	"encoding/json"
)

// Evidence defines evidence of Verifiable Credential.
type Evidence interface{}

// Issuer of the Verifiable Credential.
type Issuer struct {
	ID string `json:"id,omitempty"`

	CustomFields map[string]interface{} `json:"-"`
}

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in CustomFields.
type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`

	CustomFields map[string]interface{} `json:"-"`
}

// Credential Verifiable Credential definition.
type Credential struct {
	Context interface{} `json:"@context,omitempty"`
	ID      string      `json:"id,omitempty"`
	Type    interface{} `json:"type,omitempty"`
	// Subject can be a string, map, slice of maps, struct (Subject or any custom), slice of structs.
	Subject        interface{} `json:"credentialSubject,omitempty"`
	Issuer         *Issuer     `json:"issuer,omitempty"`
	Issued         string      `json:"issuanceDate,omitempty"`
	Expired        string      `json:"expirationDate,omitempty"`
	Proof          interface{} `json:"proof,omitempty"`
	Status         *TypedID    `json:"credentialStatus,omitempty"`
	Schemas        interface{} `json:"credentialSchema,omitempty"`
	Evidence       *Evidence   `json:"evidence,omitempty"`
	TermsOfUse     interface{} `json:"termsOfUse,omitempty"`
	RefreshService interface{} `json:"refreshService,omitempty"`
	JWT            string      `json:"jwt,omitempty"`

	CustomFields map[string]interface{} `json:"-"`
}

func NewCredential() *Credential {
	return &Credential{}
}

func (cred *Credential) FromMap(data map[string]interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, cred)
}

func (cred *Credential) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b, err := json.Marshal(cred)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(b, &ret)
	if err != nil {
		return nil
	}
	return ret
}

func (cred *Credential) Parse(raw []byte) error {
	return json.Unmarshal(raw, cred)
}

func (cred *Credential) Bytes() []byte {
	b, _ := json.Marshal(cred)
	return b
}

func (cred *Credential) Copy() *Credential {
	return &Credential{
		Context: cred.Context,
		ID:      cred.ID,
		Type:    cred.Type,
		// Subject can be a string, map, slice of maps, struct (Subject or any custom), slice of structs.
		Subject:        cred.Subject,
		Issuer:         cred.Issuer,
		Issued:         cred.Issued,
		Expired:        cred.Expired,
		Proof:          cred.Proof,
		Status:         cred.Status,
		Schemas:        cred.Schemas,
		Evidence:       cred.Evidence,
		TermsOfUse:     cred.TermsOfUse,
		RefreshService: cred.RefreshService,
		JWT:            cred.JWT,
		CustomFields:   cred.CustomFields,
	}
}

func (cred *Credential) CopyWithoutProof() *Credential {
	copied := cred.Copy()
	copied.Proof = nil
	return copied
}
