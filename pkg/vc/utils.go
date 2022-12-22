package vc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
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

func splitMessageIntoLines(msg string) []string {
	rows := strings.Split(msg, "\n")

	msgs := make([]string, 0, len(rows))

	for i := range rows {
		if strings.TrimSpace(rows[i]) != "" {
			msgs = append(msgs, rows[i])
		}
	}

	return msgs
}

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}
	return res
}

func createVerifyDocumentData(doc map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]string, []string, error) {
	docBytes, err := jsonld.Default().GetCanonicalDocument(doc, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalizing document failed: %w", err)
	}

	documentStatements := splitMessageIntoLines(string(docBytes))
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = jsonld.TransformBlankNode(row)
	}

	return documentStatements, transformedStatements, nil
}

func createVerifyProofData(proofMap map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]string, error) {
	proofMapCopy := make(map[string]interface{}, len(proofMap)-1)

	for k, v := range proofMap {
		if k != "proofValue" {
			proofMapCopy[k] = v
		}
	}

	proofBytes, err := jsonld.Default().GetCanonicalDocument(proofMapCopy, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(proofBytes)), nil
}

func createVerifyRevealData(doc map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]string, error) {
	docBytes, err := jsonld.Default().GetCanonicalDocument(doc, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(docBytes)), nil
}

func buildVerificationData(blsProof map[string]interface{}, docVerData *docVerificationData,
	opts ...jsonld.ProcessorOpts) (*verificationData, error) {
	proofStatements, err := createVerifyProofData(blsProof, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify proof data: %w", err)
	}

	numberOfProofStatements := len(proofStatements)
	revealIndexes := make([]int, numberOfProofStatements+len(docVerData.revealIndexes))

	for i := 0; i < numberOfProofStatements; i++ {
		revealIndexes[i] = i
	}

	for i := range docVerData.revealIndexes {
		revealIndexes[i+numberOfProofStatements] = numberOfProofStatements + docVerData.revealIndexes[i]
	}

	allInputStatements := append(proofStatements, docVerData.documentStatements...)
	blsMessages := toArrayOfBytes(allInputStatements)

	return &verificationData{
		blsMessages:   blsMessages,
		revealIndexes: revealIndexes,
	}, nil
}

func buildDocVerificationData(docCompacted, revealDoc map[string]interface{},
	opts ...jsonld.ProcessorOpts) (*docVerificationData, error) {
	documentStatements, transformedStatements, err := createVerifyDocumentData(docCompacted, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify document data: %w", err)
	}

	optionsWithBlankFrames := append(opts, jsonld.WithFrameBlankNodes())

	revealDocumentResult, err := jsonld.Default().Frame(docCompacted, revealDoc, optionsWithBlankFrames...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	revealDocumentStatements, err := createVerifyRevealData(revealDocumentResult, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify reveal document data: %w", err)
	}

	revealIndexes := make([]int, len(revealDocumentStatements))

	documentStatementsMap := make(map[string]int)
	for i, statement := range transformedStatements {
		documentStatementsMap[statement] = i
	}

	for i := range revealDocumentStatements {
		statement := revealDocumentStatements[i]
		statementInd := documentStatementsMap[statement]
		revealIndexes[i] = statementInd
	}

	return &docVerificationData{
		documentStatements:   documentStatements,
		revealIndexes:        revealIndexes,
		revealDocumentResult: revealDocumentResult,
	}, nil
}

func (vc *VCBuilder) applySignatureValue(context *Context, p *Proof, s []byte) {
	switch context.SignatureRepresentation {
	case SignatureProofValue:
		p.ProofValue = base64.RawURLEncoding.EncodeToString(s)
	case SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

func getProofVerifyValue(p *Proof) ([]byte, error) {

	if p.SignatureRepresentation == 0 {

		return decodeBase64(p.ProofValue)
	} else if p.SignatureRepresentation == 1 {
		return GetJWTSignature(p.JWS)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

func prepareDocAndProof(doc map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, interface{}, error) {
	docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("compact doc with security schema: %w", err)
	}

	rawProofs := docCompacted["proof"]
	if rawProofs == nil {
		return nil, nil, errors.New("document does not have a proof")
	}

	delete(docCompacted, "proof")

	return docCompacted, rawProofs, nil
}

func generateSignatureProof(blsSignature map[string]interface{}, resolver *suite.PublicKeyResolver, nonce []byte, verData *verificationData, s suite.SignatureSuite) (map[string]interface{}, error) {
	pubKeyBytes, signatureBytes, pErr := getPublicKeyAndSignature(blsSignature, resolver)
	if pErr != nil {
		return nil, fmt.Errorf("get public key and signature: %w", pErr)
	}
	signatureProofBytes, err := s.(*bbsblssignatureproof2020.BBSPSuite).SelectiveDisclosure(verData.blsMessages, signatureBytes,
		nonce, pubKeyBytes, verData.revealIndexes)
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ proof: %w", err)
	}

	derivedProof := &Proof{
		Type:               bbsblssignatureproof2020.SignatureProofType,
		Nonce:              nonce,
		VerificationMethod: blsSignature["verificationMethod"].(string),
		ProofPurpose:       blsSignature["proofPurpose"].(string),
		Created:            blsSignature["created"].(string),
		ProofValue:         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}

	return derivedProof.ToMap(), nil

}

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

func createVerifyData(s suite.SignatureSuite, jsonldDoc map[string]interface{}, proof *Proof,
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	switch proof.SignatureRepresentation {
	case SignatureProofValue:
		return createVerifyHash(s, jsonldDoc, proof.ToMap(), opts...)
	case SignatureJWS:
		return createVerifyJWS(s, jsonldDoc, proof, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", proof.SignatureRepresentation)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func createVerifyHash(s suite.SignatureSuite, jsonldDoc, proofOptions map[string]interface{},
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
	docCopy := getCopyWithoutProof(jsonldObject)

	// build canonical document
	return s.GetCanonicalDocument(docCopy, opts...)
}

// getCopyWithoutProof gets copy of JSON LD Object without proofs (signatures).
func getCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
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
func createVerifyJWS(s suite.SignatureSuite, jsonldDoc map[string]interface{}, p *Proof,
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

func createDetachedJWTHeader(alg string) string {
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
	doc := getCopyWithoutProof(jsonldObject)

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

func getProofs(appProofs interface{}) ([]map[string]interface{}, error) {
	switch p := appProofs.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil
	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))

		for i := range p {
			pp, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("proof is not a JSON map")
			}

			proofs[i] = pp
		}

		return proofs, nil
	case *Proof:
		return []map[string]interface{}{p.ToMap()}, nil
	default:
		return nil, errors.New("proof is not map or array of maps")
	}
}
func getPublicKeyAndSignature(pmap map[string]interface{}, resolver *suite.PublicKeyResolver) ([]byte, []byte, error) {
	p := NewProofFromMap(pmap)
	pid, err := p.PublicKeyId()
	if err != nil {
		return nil, nil, err
	}
	pbk := resolver.Resolve(pid)
	if pbk == nil {
		return nil, nil, fmt.Errorf("cannot resolve public key")
	}
	pubKeyValue := pbk.Value
	if p.SignatureRepresentation == SignatureJWS {
		pubKeyValue = pbk.Jwk
	}
	// get verify value
	signature, err := getProofVerifyValue(p)

	return pubKeyValue, signature, err

}

type docVerificationData struct {
	revealIndexes        []int
	revealDocumentResult map[string]interface{}
	documentStatements   []string
}

type verificationData struct {
	blsMessages   [][]byte
	revealIndexes []int
}
