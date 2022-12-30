package builder

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/utils"
)

func (builder *VCBuilder) getCompactedWithSecuritySchema() (map[string]interface{}, error) {
	docCpy := builder.credential.ToMap()
	contextMap := map[string]interface{}{
		"@context": proof.SecurityContext,
	}
	return processor.Default().Compact(docCpy, contextMap, builder.processorOpts...)
}

func getPublicKeyAndSignature(pmap map[string]interface{}, resolver *suite.PublicKeyResolver) ([]byte, []byte, error) {
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

type docVerificationData struct {
	revealIndexes        []int
	revealDocumentResult map[string]interface{}
	documentStatements   []string
}

type verificationData struct {
	blsMessages   [][]byte
	revealIndexes []int
}

func (builder *VCBuilder) buildDocVerificationData(docCompacted, revealDoc map[string]interface{}) (*docVerificationData, error) {
	// create verify document data
	docBytes, err := processor.Default().GetCanonicalDocument(docCompacted, builder.processorOpts...)
	if err != nil {
		return nil, err
	}
	documentStatements := splitMessageIntoLines(string(docBytes))
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = processor.TransformBlankNode(row)
	}
	newOpts := append(builder.processorOpts, processor.WithFrameBlankNodes())
	revealDocumentResult, err := processor.Default().Frame(docCompacted, revealDoc, newOpts...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	// create verify reveal data
	docBytes, err = processor.Default().GetCanonicalDocument(revealDocumentResult, builder.processorOpts...)
	if err != nil {
		return nil, err
	}
	revealDocumentStatements := splitMessageIntoLines(string(docBytes))

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

func (builder *VCBuilder) createVerifyProofData(proofMap map[string]interface{}) ([]string, error) {
	proofMapCopy := make(map[string]interface{}, len(proofMap)-1)

	for k, v := range proofMap {
		if k != "proofValue" {
			proofMapCopy[k] = v
		}
	}

	proofBytes, err := processor.Default().GetCanonicalDocument(proofMapCopy, builder.processorOpts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(proofBytes)), nil
}

func (builder *VCBuilder) buildVerificationData(blsProof map[string]interface{}, docVerData *docVerificationData) (*verificationData, error) {
	proofStatements, err := builder.createVerifyProofData(blsProof)
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

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}
	return res
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
	twrap := &utils.FormatedTime{}
	twrap.UnmarshalJSON([]byte(blsSignature["created"].(string)))
	derivedProof := &proof.Proof{
		Type:               bbsblssignatureproof2020.SignatureProofType,
		Nonce:              nonce,
		VerificationMethod: blsSignature["verificationMethod"].(string),
		ProofPurpose:       blsSignature["proofPurpose"].(string),
		Created:            twrap,
		ProofValue:         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}
	return derivedProof.ToMap(), err
}
