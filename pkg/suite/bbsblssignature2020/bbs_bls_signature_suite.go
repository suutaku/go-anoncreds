package bbsblssignature2020

import (
	"errors"
	"fmt"

	"github.com/suutaku/go-anoncreds/internal/tools"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

const (
	SignatureType = "BbsBlsSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type BBSSuite struct {
	priv           *bbs.PrivateKey
	verifier       suite.Verifier
	signer         suite.Signer
	blinder        *Blinder
	CompactedProof bool
	jsonldProcess  *processor.Processor
}

func NewBBSSuite(priv *bbs.PrivateKey, compacted bool) *BBSSuite {
	return &BBSSuite{
		verifier:       NewBBSG2SignatureVerifier(),
		signer:         NewBBSSigner(priv),
		CompactedProof: compacted,
		blinder:        NewBlinder(),
		jsonldProcess:  processor.Default(),
		priv:           priv,
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (bbss *BBSSuite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error) {

	return bbss.jsonldProcess.GetCanonicalDocument(doc, opts...)

}

// GetDigest returns document digest
func (bbss *BBSSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (bbss *BBSSuite) Alg() string {
	return SignatureType
}

func (bbss *BBSSuite) Sign(docByte []byte) ([]byte, error) {
	return bbss.Signer().Sign(splitMessageIntoLines(string(docByte), true))
}

func (bbss *BBSSuite) Signer() suite.Signer {
	return bbss.signer
}

func (bbss *BBSSuite) Verifier() suite.Verifier {
	return bbss.verifier
}

// Verify will verify signature against public key
func (bbss *BBSSuite) Verify(doc *credential.Credential, p *proof.Proof, resolver *suite.PublicKeyResolver, nonce []byte, opts ...processor.ProcessorOpts) error {
	// get verify data
	message, err := CreateVerifyData(bbss, doc.ToMap(), p, opts...)
	if err != nil {
		return err
	}
	pubKeyValue, signature, err := getPublicKeyAndSignature(p.ToMap(), resolver)
	if err != nil {
		return err
	}
	return bbss.Verifier().Verify(pubKeyValue, message, signature, nil)
}

const defaultProofPurpose = "assertionMethod"

// The PreBlindSign algorithm allows a holder of a signature
// to blind messages that when signed, are unknown to the signer.
// The algorithm returns a generated blinding factor that is
// used to un-blind the signature from the signer, and a pedersen
// commitment from a vector of messages and the domain parameters h and h0.
// https://identity.foundation/bbs-signature/draft-blind-bbs-signatures.html#section-5.1
func (bbssuite *BBSSuite) PreBlindSign(doc, secretDoc *credential.Credential, nonceBytes []byte, opts ...processor.ProcessorOpts) ([]byte, []byte, error) {
	if bbssuite.priv == nil {
		return nil, nil, fmt.Errorf("suite has no private key")
	}

	compactedDoc, err := getCompactedWithSecuritySchema(doc.ToMap(), opts...)
	if err != nil {
		return nil, nil, err
	}
	secret, err := getSecretStatement(compactedDoc, secretDoc.ToMap(), opts...)
	if err != nil {
		return nil, nil, err
	}
	generator, err := bbssuite.priv.PublicKey().ToPublicKeyWithGenerators(len(secret))
	if err != nil {
		return nil, nil, err
	}
	nonce := bbs.ParseProofNonce(nonceBytes)
	ctx, factory, err := bbssuite.blinder.CreateContext(secret, generator, nonce)
	return ctx.ToBytes(), factory.ToBytes(), err
}

func (bbssuite *BBSSuite) BlindSign(ctxBytes []byte, revealedMegs map[int][]byte, secretMsgCount int, pubBytes []byte, nonce []byte) ([]byte, error) {

	ctx := new(bbs.BlindSignatureContext)
	if err := ctx.FromBytes(ctxBytes); err != nil {
		return nil, err
	}
	pub, err := bbs.UnmarshalPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	generator, err := pub.ToPublicKeyWithGenerators(secretMsgCount)
	if err != nil {
		return nil, err
	}
	proofNonce := bbs.ParseProofNonce(nonce)
	blindSig, err := ctx.ToBlindSignature(revealedMegs, bbssuite.priv, generator, proofNonce)
	if err != nil {
		return nil, err
	}
	return blindSig.ToBytes()
}

func (bbs *BBSSuite) AddLinkedDataProof(lcon *proof.LinkedDataProofContext, doc *credential.Credential, opts ...processor.ProcessorOpts) (*credential.Credential, error) {
	context := lcon.ToContext()
	// validation of context
	if err := context.Validate(); err != nil {
		return nil, err
	}

	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created,
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.NewJwt().NewHeader(bbs.Alg() + "..")
	}
	message, err := CreateVerifyData(bbs, doc.ToMap(), p, opts...)
	if err != nil {
		return nil, err
	}
	sig, err := bbs.Sign(message)
	if err != nil {
		return nil, err
	}
	p.ApplySignatureValue(context, sig)
	err = doc.AddProof(p)
	return doc, err
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

// Accept registers this signature suite with the given signature type
func (bbss *BBSSuite) Accept(signatureType string) bool {
	return signatureType == SignatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (bbss *BBSSuite) CompactProof() bool {
	return bbss.CompactedProof
}

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyData(bbss suite.SignatureSuite, jsonldDoc map[string]interface{}, p *proof.Proof,
	opts ...processor.ProcessorOpts) ([]byte, error) {
	switch p.SignatureRepresentation {
	case proof.SignatureProofValue:
		return createVerifyHash(bbss, jsonldDoc, p.ToMap(), opts...)
	case proof.SignatureJWS:
		return createVerifyJWS(bbss, jsonldDoc, p, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

var jsonldContext = "@context"
var jsonldCreated = "created"
var jsonldProof = "proof"
var jsonldJWS = "jws"
var jsonldProofValue = "proofValue"

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func createVerifyHash(s suite.SignatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	// in  order to generate canonical form we need context
	// if context is not passed, use document's context
	// spec doesn't mention anything about context
	_, ok := proofOptions[jsonldContext]
	if !ok {
		proofOptions[jsonldContext] = jsonldDoc[jsonldContext]
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

func cleanProof(p map[string]interface{}) map[string]interface{} {
	ret := p
	delete(ret, "id")
	delete(ret, "proofValue")
	delete(ret, "jws")
	delete(ret, "nonce")
	return ret
}

func prepareCanonicalProofOptions(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	value, ok := proofOptions[jsonldCreated]
	if !ok || value == nil {
		return nil, errors.New("created is missing")
	}

	// copy from the original proof options map without specific keys
	proofOptionsCopy := cleanProof(proofOptions)

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

func prepareCanonicalDocument(s suite.SignatureSuite, jsonldObject map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
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
		if k != jsonldProof {
			dest[k] = v
		}
	}

	return dest
}

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

// createVerifyJWS creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func createVerifyJWS(s suite.SignatureSuite, jsonldDoc map[string]interface{}, p *proof.Proof,
	opts ...processor.ProcessorOpts) ([]byte, error) {
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
	jwtb := proof.NewJwt()
	err = jwtb.Parse(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtb.Header()+"."), verifyData...), nil
}

func prepareJWSProof(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
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
	opts ...processor.ProcessorOpts) ([]byte, error) {
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

// SelectiveDisclosure(blsMessages [][]byte, signature, nonce, pubKeyBytes []byte, revIndexes []int) ([]byte, error)
func (bbss *BBSSuite) SelectiveDisclosure(doc, revealDoc *credential.Credential, pubKey *suite.PublicKey, nonce []byte, opts ...processor.ProcessorOpts) (*credential.Credential, error) {
	panic("bbsblssignatrure suite has no implementation of SelectiveDisclosure")
}

// func getRevealedStatement(docCompacted, secret map[string]interface{}, opts ...processor.ProcessorOpts) (map[int][]byte, error) {
// 	// create verify document data
// 	docBytes, err := processor.Default().GetCanonicalDocument(docCompacted, opts...)
// 	if err != nil {
// 		return nil, err
// 	}
// 	documentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
// 	transformedDocStatements := make(map[int][]byte, 0)

// 	for i, row := range documentStatements {
// 		transformedDocStatements[i] = []byte(processor.TransformBlankNode(string(row)))
// 	}
// 	newOpts := append(opts, processor.WithFrameBlankNodes())
// 	secretDocumentResult, err := processor.Default().Frame(docCompacted, secret, newOpts...)
// 	if err != nil {
// 		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
// 	}

// 	// create verify reveal data
// 	docBytes, err = processor.Default().GetCanonicalDocument(secretDocumentResult, opts...)
// 	if err != nil {
// 		return nil, err
// 	}
// 	secretDocumentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
// 	transformedSecretStatements := make(map[int][]byte, 0)
// 	for i, row := range secretDocumentStatements {
// 		transformedSecretStatements[i] = []byte(row)
// 	}

// 	transformedrevealedDocumentStatements := make(map[int][]byte, 0)
// 	for i, row := range transformedDocStatements {
// 		if _, contains := transformedSecretStatements[i]; !contains {
// 			transformedrevealedDocumentStatements[i] = []byte(row)
// 		}
// 	}

// 	return transformedrevealedDocumentStatements, nil
// }

func getSecretStatement(docCompacted, secret map[string]interface{}, opts ...processor.ProcessorOpts) (map[int][]byte, error) {
	// create verify document data
	docBytes, err := processor.Default().GetCanonicalDocument(docCompacted, opts...)
	if err != nil {
		return nil, err
	}
	documentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
	transformedDocStatements := make(map[int][]byte, 0)

	for i, row := range documentStatements {
		transformedDocStatements[i] = []byte(processor.TransformBlankNode(string(row)))
	}
	newOpts := append(opts, processor.WithFrameBlankNodes())
	secretDocumentResult, err := processor.Default().Frame(docCompacted, secret, newOpts...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	// create verify reveal data
	docBytes, err = processor.Default().GetCanonicalDocument(secretDocumentResult, opts...)
	if err != nil {
		return nil, err
	}
	secretDocumentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
	transformedSecretStatements := make(map[int][]byte, 0)
	for i, row := range secretDocumentStatements {
		transformedSecretStatements[i] = []byte(row)
	}

	return transformedSecretStatements, nil
}
