package bbsblssignatureproof2020

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/suutaku/go-anoncreds/internal/tools"
	resolver "github.com/suutaku/go-anoncreds/pkg/key-resolver"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/utils"
)

const (
	SignatureType      = "BbsBlsSignature2020"
	SignatureProofType = "BbsBlsSignatureproof2020"
	rdfDataSetAlg      = "URDNA2015"
)

type BBSPSuite struct {
	verifier        suite.Verifier
	signer          suite.Signer
	CompactedProof  bool
	jsonldProcessor *processor.Processor
}

func NewBBSPSuite(priv *bbs.PrivateKey, compated bool) *BBSPSuite {
	return &BBSPSuite{
		verifier:        NewBBSG2SignatureProofVerifier(),
		signer:          NewBBSSigProofSigner(priv),
		CompactedProof:  compated,
		jsonldProcessor: processor.Default(),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSPSuite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error) {
	if v, ok := doc["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, SignatureProofType) {
			docType = strings.Replace(docType, SignatureProofType, SignatureType, 1)
			doc["type"] = docType
		}
	}

	return bbss.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest
func (bbss *BBSPSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSPSuite) Alg() string {
	return SignatureProofType
}

func (bbss *BBSPSuite) Sign(docByte []byte) ([]byte, error) {

	return bbss.signer.Sign(tools.SplitMessageIntoLines(string(docByte), true))
}

// Verify will verify signature against public key
func (bbss *BBSPSuite) Verify(doc *credential.Credential, p *proof.Proof, resolver resolver.PublicKeyResolver, nonce []byte, opts ...processor.ProcessorOpts) error {

	// get verify data
	message, err := bbsblssignature2020.CreateVerifyData(bbss, doc.ToMap(), p, opts...)
	if err != nil {
		return err
	}
	pubKeyValue, signature, err := getPublicKeyAndSignature(p.ToMap(), resolver)
	if err != nil {
		return err
	}
	return bbss.Verifier().Verify(pubKeyValue, message, signature, nonce)
}

// Accept registers this signature suite with the given signature type
func (bbss *BBSPSuite) Accept(signatureType string) bool {
	return signatureType == SignatureProofType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSPSuite) CompactProof() bool {
	return bbss.CompactedProof
}

// func (bbs *BBSPSuite) SelectiveDisclosure(blsMessages [][]byte, signature, nonce, pubKeyBytes []byte, revIndexes []int) ([]byte, error) {
// 	return bbs.Signer.(*BBSSigProofSigner).DeriveProof(blsMessages, signature, nonce, pubKeyBytes, revIndexes)
// }

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://w3id.org/security/jws/v1"
)

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...processor.ProcessorOpts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return processor.Default().Compact(docMap, contextMap, opts...)
}

func buildDocVerificationData(docCompacted, revealDoc map[string]interface{}, opts ...processor.ProcessorOpts) (*suite.DocVerificationData, error) {
	// create verify document data
	docBytes, err := processor.Default().GetCanonicalDocument(docCompacted, opts...)
	if err != nil {
		return nil, err
	}
	documentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = processor.TransformBlankNode(string(row))
	}
	newOpts := append(opts, processor.WithFrameBlankNodes())
	revealDocumentResult, err := processor.Default().Frame(docCompacted, revealDoc, newOpts...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	// create verify reveal data
	docBytes, err = processor.Default().GetCanonicalDocument(revealDocumentResult, opts...)
	if err != nil {
		return nil, err
	}
	revealDocumentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)

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

	return &suite.DocVerificationData{
		DocumentStatements:   documentStatements,
		RevealIndexes:        revealIndexes,
		RevealDocumentResult: revealDocumentResult,
	}, nil
}

func (bbs *BBSPSuite) SelectiveDisclosure(doc, revealDoc *credential.Credential, pubKey *resolver.PublicKey, nonce []byte, opts ...processor.ProcessorOpts) (*credential.Credential, error) {
	if doc == nil {
		return nil, fmt.Errorf("no credential parsed")
	}
	if doc.Proof == nil {
		return nil, fmt.Errorf("expected at least one proof present")
	}

	docWithoutProof, err := getCompactedWithSecuritySchema(doc.ToMap(), opts...)
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}
	blsSignatures, err := credential.GetBLSProofs(docWithoutProof["proof"])
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}
	delete(docWithoutProof, "proof")
	if len(blsSignatures) == 0 {
		return nil, fmt.Errorf("no BbsBlsSignature2020 proof present")
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
		resolver := resolver.NewTestPublicKeyResolver(pubKey, nil)
		derivedProof, dErr := generateSignatureProof(blsSignature, resolver, nonce, verData, bbs)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.RevealDocumentResult
	revealDocumentResult["proof"] = proofs
	ret := credential.NewCredential()
	ret.FromMap(revealDocumentResult)
	return ret, nil
}

func (bbss *BBSPSuite) Signer() suite.Signer {
	return bbss.signer
}

func (bbss *BBSPSuite) Verifier() suite.Verifier {
	return bbss.verifier
}

func (bbss *BBSPSuite) AddLinkedDataProof(lcon *proof.LinkedDataProofContext, doc *credential.Credential, opts ...processor.ProcessorOpts) (*credential.Credential, error) {
	panic("bbsblssignatureproof suite has no implementation of AddLinkedDataProof")
}

func generateSignatureProof(blsSignature map[string]interface{}, resolver resolver.PublicKeyResolver, nonce []byte, verData *suite.VerificationData, s suite.SignatureSuite) (map[string]interface{}, error) {
	pubKeyBytes, signatureBytes, pErr := getPublicKeyAndSignature(blsSignature, resolver)
	if pErr != nil {
		return nil, fmt.Errorf("get public key and signature: %w", pErr)
	}

	signatureProofBytes, err := s.Signer().(*BBSSigProofSigner).DeriveProof(verData.BlsMessages, signatureBytes, nonce, pubKeyBytes, verData.RevealIndexes)
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ proof: %w", err)
	}
	twrap := &utils.FormatedTime{}
	twrap.UnmarshalJSON([]byte(blsSignature["created"].(string)))
	derivedProof := &proof.Proof{
		Type:               SignatureProofType,
		Nonce:              nonce,
		VerificationMethod: blsSignature["verificationMethod"].(string),
		ProofPurpose:       blsSignature["proofPurpose"].(string),
		Created:            twrap,
		ProofValue:         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}
	return derivedProof.ToMap(), err
}

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}
	return res
}

func buildVerificationData(blsProof map[string]interface{}, docVerData *suite.DocVerificationData, opts ...processor.ProcessorOpts) (*suite.VerificationData, error) {
	proofStatements, err := createVerifyProofData(blsProof, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify proof data: %w", err)
	}

	numberOfProofStatements := len(proofStatements)
	revealIndexes := make([]int, numberOfProofStatements+len(docVerData.RevealIndexes))

	for i := 0; i < numberOfProofStatements; i++ {
		revealIndexes[i] = i
	}

	for i := range docVerData.RevealIndexes {
		revealIndexes[i+numberOfProofStatements] = numberOfProofStatements + docVerData.RevealIndexes[i]
	}

	allInputStatements := append(proofStatements, docVerData.DocumentStatements...)
	blsMessages := toArrayOfBytes(allInputStatements)

	return &suite.VerificationData{
		BlsMessages:   blsMessages,
		RevealIndexes: revealIndexes,
	}, nil
}

func createVerifyProofData(proofMap map[string]interface{}, opts ...processor.ProcessorOpts) ([]string, error) {
	proofMapCopy := make(map[string]interface{}, len(proofMap)-1)

	for k, v := range proofMap {
		if k != "proofValue" {
			proofMapCopy[k] = v
		}
	}

	proofBytes, err := processor.Default().GetCanonicalDocument(proofMapCopy, opts...)
	if err != nil {
		return nil, err
	}

	return tools.SplitMessageIntoLinesStr(string(proofBytes), false), nil
}

func getPublicKeyAndSignature(pmap map[string]interface{}, resolver resolver.PublicKeyResolver) ([]byte, []byte, error) {
	p := proof.NewProofFromMap(pmap)
	pid, err := p.PublicKeyId()
	if err != nil {
		return nil, nil, err
	}
	pbk := resolver.Resolve(pid)
	if pbk == nil {
		return nil, nil, fmt.Errorf("cannot resolve public key")
	}
	pubKeyValue := pbk.Value
	if p.SignatureRepresentation == proof.SignatureJWS {
		pubKeyValue = pbk.Jwk
	}
	// get verify value
	signature, err := p.GetProofVerifyValue()

	return pubKeyValue, signature, err

}
