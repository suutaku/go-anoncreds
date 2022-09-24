package vc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
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

// var (
// 	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
// )

// func excludedKeyFromString(s string) string {
// 	for _, ek := range excludedKeysStr {
// 		if ek == s {
// 			return ek
// 		}
// 	}

// 	return ""
// }

func prepareCanonicalProofOptions(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	value, ok := proofOptions["created"]
	if !ok || value == nil {
		return nil, errors.New("created is missing")
	}

	// copy from the original proof options map without specific keys
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		if excludedKeyFromString(key) == 0 {
			proofOptionsCopy[key] = value
		}
	}

	if s.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy, opts...)
		if err != nil {
			return nil, err
		}

		proofOptionsCopy = docCompacted
	}

	// build canonical proof options
	return s.GetCanonicalDocument(proofOptionsCopy, opts...)
}

type excludedKey uint

func (ek excludedKey) String() string {
	return excludedKeysStr[ek-1]
}

const (
	proofID excludedKey = iota + 1
	proofValue
	jws
	nonce
)

var (
	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
	excludedKeys    = [...]excludedKey{proofID, proofValue, jws, nonce}
)

func excludedKeyFromString(s string) excludedKey {
	for _, ek := range excludedKeys {
		if ek.String() == s {
			return ek
		}
	}

	return 0
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return jsonld.Default().Compact(docMap, contextMap, opts...)
}

func CreateVerifyData(s suite.SignatureSuite, jsonldDoc map[string]interface{}, proof *Proof,
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	switch proof.SignatureRepresentation {
	case SignatureProofValue:
		return CreateVerifyHash(s, jsonldDoc, proof.ToMap(), opts...)
	case SignatureJWS:
		return CreateVerifyJWS(s, jsonldDoc, proof, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", proof.SignatureRepresentation)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func CreateVerifyHash(s suite.SignatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// in  order to generate canonical form we need context
	// if context is not passed, use document's context
	// spec doesn't mention anything about context
	_, ok := proofOptions["@context"]
	if !ok {
		proofOptions["@context"] = jsonldDoc["@context"]
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(s, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := s.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareCanonicalDocument(s, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := s.GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

func prepareCanonicalDocument(s suite.SignatureSuite, jsonldObject map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	docCopy := GetCopyWithoutProof(jsonldObject)

	// build canonical document
	return s.GetCanonicalDocument(docCopy, opts...)
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
func CreateVerifyJWS(s suite.SignatureSuite, jsonldDoc map[string]interface{}, p *Proof,
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	proofOptions := p.ToMap()

	canonicalProofOptions, err := prepareJWSProof(s, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := s.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(s, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := s.GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)

	jwtHeader, err := getJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

func CreateDetachedJWTHeader(alg string) string {
	jwtHeaderMap := map[string]interface{}{
		"alg":  alg,
		"b64":  false,
		"crit": []string{"b64"},
	}

	jwtHeaderBytes, err := json.Marshal(jwtHeaderMap)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(jwtHeaderBytes)
}

func prepareJWSProof(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions[jsonldContext] = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		proofOptionsCopy[key] = value
	}

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofValue)

	return s.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func prepareDocumentForJWS(s suite.SignatureSuite, jsonldObject map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	doc := GetCopyWithoutProof(jsonldObject)

	if s.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
		if err != nil {
			return nil, err
		}

		doc = docCompacted
	}

	// build canonical document
	return s.GetCanonicalDocument(doc, opts...)
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

func AddProof(cred *Credential, p *Proof) error {
	if cred.Proof != nil {
		var proofs []interface{}
		switch p := cred.Proof.(type) {
		case []interface{}:
			proofs = p
		default:
			proofs = []interface{}{p}
		}
		proofs = append(proofs, p)
		cred.Proof = proofs
	}
	cred.Proof = p
	return nil
}

func getBlsProofs(rawProofs interface{}) ([]map[string]interface{}, error) {
	allProofs, err := getProofs(rawProofs)
	if err != nil {
		return nil, fmt.Errorf("read document proofs: %w", err)
	}

	blsProofs := make([]map[string]interface{}, 0)

	for _, p := range allProofs {
		proofType, ok := p["type"].(string)
		if ok && strings.HasSuffix(proofType, bbsBlsSignature2020) {
			p["@context"] = securityContext
			blsProofs = append(blsProofs, p)
		}
	}

	return blsProofs, nil
}
