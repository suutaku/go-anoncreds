package vc

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
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

	message, err := CreateVerifyData(suit, builder.credential, p)
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

func getProofs(raw interface{}) []*Proof {
	proofs := make([]*Proof, 0)
	switch x := raw.(type) {
	case []interface{}:
		for _, v := range x {
			tmp := Proof{}
			cfg := &mapstructure.DecoderConfig{
				Metadata: nil,
				Result:   &tmp,
				TagName:  "json",
			}
			decoder, _ := mapstructure.NewDecoder(cfg)
			decoder.Decode(v)
			proofs = append(proofs, &tmp)
		}
	case interface{}:
		tmp := Proof{}
		cfg := &mapstructure.DecoderConfig{
			Metadata: nil,
			Result:   &tmp,
			TagName:  "json",
		}
		decoder, _ := mapstructure.NewDecoder(cfg)
		decoder.Decode(x)
		proofs = append(proofs, &tmp)
	case []*Proof:
		for _, v := range x {
			proofs = append(proofs, v)
		}
	case *Proof:
		proofs = append(proofs, x)
	case Proof:
		proofs = append(proofs, &x)
	}
	return proofs
}

func getPublicKeyAndSignature(p *Proof, resolver *suite.PublicKeyResolver) ([]byte, []byte, error) {
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
	proofs := getProofs(builder.credential.Proof)
	for _, p := range proofs {

		suit := builder.signatureSuite[p.Type]
		if suit == nil {
			return fmt.Errorf("cannot get singanture suite for type: %s", p.Type)
		}
		// get verify data
		message, err := CreateVerifyData(suit, builder.credential, p)
		if err != nil {
			return err
		}
		pubKeyValue, signature, err := getPublicKeyAndSignature(p, resolver)
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

func (builder *VCBuilder) GenerateBBSSelectiveDisclosure(revealDoc *Credential, pubKey *suite.PublicKey, nonce []byte) (*Credential, error) {
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

	docWithoutProof := builder.credential.CopyWithoutProof()
	blsSignatures := GetBlsProofs(builder.credential.Proof)

	if len(blsSignatures) == 0 {
		return nil, fmt.Errorf("no BbsBlsSignature2020 proof present")
	}

	docVerData, pErr := buildDocVerificationData(docWithoutProof, revealDoc, s)
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}

	resolver := suite.NewPublicKeyResolver(pubKey, nil)

	proofs := make([]*Proof, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := buildVerificationData(blsSignature, docVerData, s)
		if dErr != nil {
			return nil, fmt.Errorf("build verification data: %w", dErr)
		}

		derivedProof, dErr := generateSignatureProof(blsSignature, resolver, nonce, verData, s)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.revealDocumentResult
	revealDocumentResult["proof"] = proofs

	ret := NewCredential()
	err := ret.FromMap(revealDocumentResult)

	return ret, err
}

func generateSignatureProof(blsSignature *Proof, resolver *suite.PublicKeyResolver, nonce []byte, verData *verificationData, s suite.SignatureSuite) (*Proof, error) {
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
		VerificationMethod: blsSignature.VerificationMethod,
		ProofPurpose:       blsSignature.ProofPurpose,
		Created:            blsSignature.Created,
		ProofValue:         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}

	return derivedProof, nil

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

func buildVerificationData(blsProof *Proof, docVerData *docVerificationData, s suite.SignatureSuite) (*verificationData, error) {
	proofStatements, err := createVerifyProofData(blsProof, s)
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

func buildDocVerificationData(docCompacted, revealDoc *Credential, s suite.SignatureSuite) (*docVerificationData, error) {
	documentStatements, transformedStatements, err := createVerifyDocumentData(docCompacted, s)
	if err != nil {
		return nil, fmt.Errorf("create verify document data: %w", err)
	}

	revealDocumentResult, err := jsonld.Default().Frame(docCompacted.ToMap(), revealDoc.ToMap(), jsonld.WithFrameBlankNodes())
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}
	cnvrt := NewCredential()
	cnvrt.FromMap(revealDocumentResult)
	revealDocumentStatements, err := createVerifyRevealData(cnvrt, s)
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

func createVerifyProofData(cred *Proof, s suite.SignatureSuite) ([]string, error) {
	copied := cred.Copy()
	copied.ProofValue = ""

	proofBytes, err := s.GetCanonicalDocument(copied)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(proofBytes)), nil
}

func createVerifyRevealData(cred *Credential, s suite.SignatureSuite) ([]string, error) {
	docBytes, err := s.GetCanonicalDocument(cred)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(docBytes)), nil
}

func createVerifyDocumentData(cred *Credential, s suite.SignatureSuite) ([]string, []string, error) {
	docBytes, err := s.GetCanonicalDocument(cred)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalizing document failed: %w", err)
	}

	documentStatements := splitMessageIntoLines(string(docBytes))
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = TransformBlankNode(row)
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
