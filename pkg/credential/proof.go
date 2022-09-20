package credential

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"
)

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://w3id.org/security/jws/v1"
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
	SignatureRepresentation int
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{} `json:"capabilityChain,omitempty"`
}

func NewProof(ptype string) *Proof {
	return &Proof{
		Type: ptype,
	}
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

var (
	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
)

func excludedKeyFromString(s string) string {
	for _, ek := range excludedKeysStr {
		if ek == s {
			return ek
		}
	}

	return ""
}

func prepareCanonicalProofOptions(proofOptions *Proof) ([]byte, error) {
	// if proofOptions.Created.IsZero() {
	// 	return nil, fmt.Errorf("created is missing")
	// }

	// copy from the original proof options map without specific keys
	proofOptionsCopy := proofOptions.CopyWithoutSecuritySchemas()

	// if s.CompactProof() {

	// 	docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	proofOptionsCopy = docCompacted
	// }

	// build canonical proof options
	return GetCanonicalDocument(proofOptionsCopy)
}

func getCompactedWithSecuritySchema(docMap interface{}) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}
	opt := ld.NewJsonLdOptions("")
	return ld.NewJsonLdProcessor().Compact(docMap, contextMap, opt)
}

func CreateVerifyData(cred *Credential, p *Proof) ([]byte, error) {
	if p.SignatureRepresentation == 0 {
		return CreateVerifyHash(cred, p)
	} else if p.SignatureRepresentation == 1 {
		return CreateVerifyJWS(cred, p)
	}
	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func CreateVerifyHash(jsonldDoc *Credential, proofOptions *Proof) ([]byte, error) {

	if proofOptions.Context == nil {
		proofOptions.Context = jsonldDoc.Context
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(proofOptions)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareCanonicalDocument(jsonldDoc)
	if err != nil {
		return nil, err
	}

	docDigest := GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

func prepareCanonicalDocument(jsonldObject *Credential) ([]byte, error) {
	// copy document object without proof
	docCopy := jsonldObject.CopyWithoutProof()

	// build canonical document
	return GetCanonicalDocument(docCopy)
}

// GetCopyWithoutProof gets copy of JSON LD Object without proofs (signatures).
func GetCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
	if jsonLdObject == nil {
		return nil
	}

	dest := make(map[string]interface{})

	for k, v := range jsonLdObject {
		if k != "proof" {
			dest[k] = v
		}
	}

	return dest
}

// createVerifyJWS creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func CreateVerifyJWS(jsonldDoc *Credential, p *Proof) ([]byte, error) {

	canonicalProofOptions, err := prepareJWSProof(p)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(jsonldDoc)
	if err != nil {
		return nil, err
	}

	docDigest := GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)

	jwtHeader, err := getJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

func prepareJWSProof(proofOptions *Proof) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions.Context = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := proofOptions.CopyWithoutSecuritySchemas()

	return GetCanonicalDocument(proofOptionsCopy)
}

func prepareDocumentForJWS(jsonldObject *Credential) ([]byte, error) {
	// copy document object without proof
	doc := jsonldObject.CopyWithoutProof()

	// if suite.CompactProof() {
	// 	docCompacted, err := getCompactedWithSecuritySchema(doc)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	doc = docCompacted
	// }

	// build canonical document
	return GetCanonicalDocument(doc)
}

const (
	jwtPartsNumber   = 3
	jwtHeaderPart    = 0
	jwtSignaturePart = 2
)

func getJWTHeader(jwt string) (string, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber {
		return "", errors.New("invalid JWT")
	}

	return jwtParts[jwtHeaderPart], nil
}

// GetJWTSignature returns signature part of JWT.
func GetJWTSignature(jwt string) ([]byte, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber || jwtParts[jwtSignaturePart] == "" {
		return nil, errors.New("invalid JWT")
	}

	return base64.RawURLEncoding.DecodeString(jwtParts[jwtSignaturePart])
}
