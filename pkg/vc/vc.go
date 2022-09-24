package vc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/suutaku/go-anoncreds/internal/jsonld"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
)

const defaultProofPurpose = "assertionMethod"

// Context holds signing options and private key.
type Context struct {
	SignatureType           string        // required
	Creator                 string        // required
	SignatureRepresentation int           // optional
	Created                 time.Time     // optional
	Domain                  string        // optional
	Nonce                   []byte        // optional
	VerificationMethod      string        // optional
	Challenge               string        // optional
	Purpose                 string        // optional
	CapabilityChain         []interface{} // optional
}

type VCBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	credential     *Credential
}

func NewVCBuilder(cred *Credential) *VCBuilder {
	return &VCBuilder{
		signatureSuite: make(map[string]suite.SignatureSuite),
		credential:     cred,
	}
}

func (builder *VCBuilder) AddSuite(s suite.SignatureSuite) {
	builder.signatureSuite[s.Alg()] = s
}

func (builder *VCBuilder) build(context *Context) error {
	// validation of context
	if context.SignatureType == "" {
		return fmt.Errorf("signature type is missing")
	}
	if context.Created.IsZero() {
		context.Created = time.Now()
	}
	if context.Purpose == "" {
		context.Purpose = defaultProofPurpose
	}

	// get signature suit
	suit := builder.signatureSuite[context.SignatureType]
	if suit == nil {
		return fmt.Errorf("cannot get signature suite with type: %s", context.SignatureType)
	}

	// construct proof
	p := &Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created.String(),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}

	if context.SignatureRepresentation == SignatureJWS {
		p.JWS = CreateDetachedJWTHeader(suit.Alg() + "..")
	}

	message, err := CreateVerifyData(suit, builder.credential.ToMap(), p)
	if err != nil {
		return err
	}
	sig, err := suit.Sign(message)
	if err != nil {
		return err
	}

	builder.applySignatureValue(context, p, sig)
	return AddProof(builder.credential, p)
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

func (builder *VCBuilder) Verify(resolver *suite.PublicKeyResolver) error {
	if builder.credential == nil {
		return fmt.Errorf("credential was empty")
	}
	if builder.credential.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs, err := getProofs(builder.credential.Proof)
	if err != nil {
		return err
	}
	for _, pm := range proofs {
		p := NewProofFromMap(pm)
		suit := builder.signatureSuite[pm["type"].(string)]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", pm["type"].(string))
		}
		// get verify data
		message, err := CreateVerifyData(suit, builder.credential.ToMap(), p)
		if err != nil {
			return err
		}
		pubKeyValue, signature, err := getPublicKeyAndSignature(pm, resolver)
		if err != nil {
			return err
		}
		err = suit.Verify(message, pubKeyValue, signature)
		if err != nil {
			return err
		}
	}
	return nil
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

func (builder *VCBuilder) AddLinkedDataProof(lcon *LinkedDataProofContext) error {
	context := mapContext(lcon)
	return builder.build(context)
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

func (builder *VCBuilder) GenerateBBSSelectiveDisclosure(revealDoc *Credential, pubKey *suite.PublicKey, nonce []byte, opts ...jsonld.ProcessorOpts) (*Credential, error) {
	if builder.credential == nil {
		return nil, fmt.Errorf("no credential parsed")
	}
	if builder.credential.Proof == nil {
		return nil, fmt.Errorf("expected at least one proof present")
	}
	s := builder.signatureSuite[bbsblssignatureproof2020.SignatureProofType]
	if s == nil {
		return nil, fmt.Errorf("expected at least one signature suit present")
	}

	docWithoutProof, rawProofs, err := prepareDocAndProof(builder.credential.ToMap(), opts...)
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}

	blsSignatures, err := getBlsProofs(rawProofs)
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}

	if len(blsSignatures) == 0 {
		return nil, errors.New("no BbsBlsSignature2020 proof present")
	}

	docVerData, pErr := buildDocVerificationData(docWithoutProof, revealDoc.ToMap(), opts...)
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}

	proofs := make([]map[string]interface{}, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := buildVerificationData(blsSignature, docVerData, opts...)
		if dErr != nil {
			return nil, fmt.Errorf("build verification data: %w", dErr)
		}
		resolver := suite.NewPublicKeyResolver(pubKey, nil)
		derivedProof, dErr := generateSignatureProof(blsSignature, resolver, nonce, verData, s)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.revealDocumentResult
	revealDocumentResult["proof"] = proofs
	ret := NewCredential()
	ret.FromMap(revealDocumentResult)
	return ret, nil
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

type docVerificationData struct {
	revealIndexes        []int
	revealDocumentResult map[string]interface{}
	documentStatements   []string
}

type verificationData struct {
	blsMessages   [][]byte
	revealIndexes []int
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

// TransformBlankNode replaces blank node identifiers in the RDF statements.
// For example, transform from "_:c14n0" to "urn:bnid:_:c14n0".
func TransformBlankNode(row string) string {
	prefixIndex := strings.Index(row, "_:c14n")
	if prefixIndex < 0 {
		return row
	}

	sepIndex := strings.Index(row[prefixIndex:], " ")
	if sepIndex < 0 {
		sepIndex = len(row)
	} else {
		sepIndex += prefixIndex
	}

	prefix := row[:prefixIndex]
	blankNode := row[prefixIndex:sepIndex]
	suffix := row[sepIndex:]

	return fmt.Sprintf("%s<urn:bnid:%s>%s", prefix, blankNode, suffix)
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
