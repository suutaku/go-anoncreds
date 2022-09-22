package test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-anoncreds/pkg/vc"
	"github.com/suutaku/go-bbs/pkg/bbs"
)

func TestSuite(t *testing.T) {
	cred := vc.NewCredential()
	cred.Parse([]byte(vcDoc))

	pub, priv, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)
	bbsSuite := bbsblssignature2020.NewBBSSuite(bbsblssignature2020.NewBBSG2SignatureVerifier(), bbsblssignature2020.NewBBSSigner(priv), true)

	pubKeyBytes, err := pub.Marshal()
	require.NoError(t, err)
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: pubKeyBytes, Type: "Bls12381G2Key2020"}, nil)
	builder := vc.NewVCBuilder(cred)
	builder.AddSuite(bbsSuite)

	// do sign
	ldpContext := &vc.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: vc.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
	}
	err = builder.AddLinkedDataProof(ldpContext)
	require.NoError(t, err)
	err = builder.Verify(resolver)
	require.NoError(t, err)
}
