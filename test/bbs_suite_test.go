package test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/suutaku/go-anoncreds/pkg/builder"
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
)

var cred *credential.Credential
var priv *bbs.PrivateKey
var pubKeyBytes []byte

func linkedDataProof(t *testing.T) {
	cred = credential.NewCredential()
	cred.FromBytes([]byte(vcDoc))

	pub, priv, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)
	bbsSuite := bbsblssignature2020.NewBBSSuite(bbsblssignature2020.NewBBSG2SignatureVerifier(), bbsblssignature2020.NewBBSSigner(priv), false)

	pubKeyBytes, err = pub.Marshal()
	require.NoError(t, err)

	builder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	builder.AddSuite(bbsSuite)

	// do sign
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
	}
	err = builder.AddLinkedDataProof(ldpContext)
	require.NoError(t, err)
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: pubKeyBytes, Type: "Bls12381G2Key2020"}, nil)
	err = builder.Verify(resolver)
	require.NoError(t, err)
	t.Log(cred.ToString())
}

func TestSelectiveDisclosure(t *testing.T) {
	linkedDataProof(t)
	bbspsuite := bbsblssignatureproof2020.NewBBSPSuite(
		bbsblssignatureproof2020.NewBBSG2SignatureProofVerifier([]byte("nonce")),
		bbsblssignatureproof2020.NewBBSSigProofSigner(priv), false)

	bbsSuite := bbsblssignature2020.NewBBSSuite(bbsblssignature2020.NewBBSG2SignatureVerifier(), nil, false)

	rev := credential.NewCredential()
	err := rev.FromBytes([]byte(revealJSON))
	require.NoError(t, err)

	selectBuilder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	selectBuilder.AddSuite(bbspsuite)
	selectBuilder.AddSuite(bbsSuite)
	disclu, err := selectBuilder.GenerateBBSSelectiveDisclosure(rev, &suite.PublicKey{Value: pubKeyBytes, Type: "Bls12381G2Key2020"}, []byte("nonce"))
	require.NoError(t, err)
	t.Logf("%s\n", disclu.ToString())
	// fmt.Println(disclu.String())
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: pubKeyBytes, Type: "Bls12381G2Key2020"}, nil)
	discluBuilder := builder.NewVCBuilder(disclu, processor.WithValidateRDF())
	discluBuilder.AddSuite(bbspsuite)
	// discluBuilder.AddSuite(bbsSuite)
	err = discluBuilder.Verify(resolver)
	require.NoError(t, err)
}
