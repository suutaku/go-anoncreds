package suite

import (
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

// SignatureSuite encapsulates signature suite methods required for signature verification.
type SignatureSuite interface {
	Signer() Signer

	Verifier() Verifier
	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	Sign(doc []byte) ([]byte, error)

	// Verify will verify signature against public key
	Verify(doc *credential.Credential, p *proof.Proof, resolver *PublicKeyResolver, opts ...processor.ProcessorOpts) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool

	// Alg will return algorithm
	Alg() string

	AddLinkedDataProof(lcon *proof.LinkedDataProofContext, doc *credential.Credential, opts ...processor.ProcessorOpts) (*credential.Credential, error)

	//SelectiveDisclosure(blsMessages [][]byte, signature, nonce, pubKeyBytes []byte, revIndexes []int) ([]byte, error)
	SelectiveDisclosure(doc, revealDoc *credential.Credential, pubKey *PublicKey, nonce []byte, opts ...processor.ProcessorOpts) (*credential.Credential, error)
}
