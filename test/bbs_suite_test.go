package test

import (
	"encoding/hex"
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
	"github.com/suutaku/go-vc/pkg/utils"
)

func TestSignAndDisclosure(t *testing.T) {
	// issuer load example credential
	cred := credential.NewCredential()
	err := cred.FromBytes([]byte(vcDoc))
	require.NoError(t, err)

	// issuer and holder key pair
	issuerPrivateKeyBytes, _ := hex.DecodeString("4b47459199b0c2210de9d28c1412551c28c57caae60872aa677bc9af2038d22b")
	holderPrivateKeyByets, _ := hex.DecodeString("63e5cd2c608861a712f003254d6bf5f5f5921651e323162bea78d0f5e7d77225")

	issuerPrivateKey, err := bbs.UnmarshalPrivateKey(issuerPrivateKeyBytes)
	require.NoError(t, err)
	issuerPublicKey := issuerPrivateKey.PublicKey()
	issuerPublicKeyBytes, err := issuerPublicKey.Marshal()
	require.NoError(t, err)

	holderPrivateKey, err := bbs.UnmarshalPrivateKey(holderPrivateKeyByets)
	require.NoError(t, err)

	// issuer create signature suite
	bbsSuite := bbsblssignature2020.NewBBSSuite(issuerPrivateKey, false)
	require.NotNil(t, bbsSuite)

	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(bbsSuite)

	// issuer sign credential
	created := new(utils.FormatedTime)
	created.UnmarshalJSON([]byte("2019-12-03T12:19:52Z"))
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
		Created:                 created,
	}
	sigDoc, err := issuerBuilder.AddLinkedDataProof(ldpContext)
	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	// issuer verify with public key
	resolver := suite.NewPublicKeyResolver(
		&suite.PublicKey{
			Value: issuerPublicKeyBytes,
			Type:  "Bls12381G2Key2020",
		},
		nil)
	err = issuerBuilder.Verify(resolver, []byte("nonce"))
	require.NoError(t, err)

	// holder create suite
	holderBbspsuite := bbsblssignatureproof2020.NewBBSPSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbspsuite)
	holderBbsSuite := bbsblssignature2020.NewBBSSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbsSuite)

	// holder load revealed VC
	rev := credential.NewCredential()
	err = rev.FromBytes([]byte(revealJSON))
	require.NoError(t, err)

	// holder create builder
	holderBuilder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	holderBuilder.AddSuite(holderBbspsuite)
	holderBuilder.AddSuite(holderBbsSuite)

	// holder create selective disclouser with public key
	nonce := []byte("nonce")
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(
		rev,
		&suite.PublicKey{
			Value: issuerPublicKeyBytes,
			Type:  "Bls12381G2Key2020",
		},
		nonce)
	require.NoError(t, err)
	require.Empty(t, disclu.Issued)
	require.NotEmpty(t, disclu.Expired)

	// verifier verify VC with issuer's public key
	verifier := builder.NewVCBuilder(disclu, processor.WithValidateRDF())
	verifier.AddSuite(bbsblssignatureproof2020.NewBBSPSuite(nil, false))
	err = verifier.Verify(resolver, nonce)
	require.NoError(t, err)

}

func TestBlindSignAndDisclosure(t *testing.T) {

	issuerPrivateKeyBytes, _ := hex.DecodeString("4b47459199b0c2210de9d28c1412551c28c57caae60872aa677bc9af2038d22b")
	holderPrivateKeyByets, _ := hex.DecodeString("63e5cd2c608861a712f003254d6bf5f5f5921651e323162bea78d0f5e7d77225")

	issuerPrivateKey, err := bbs.UnmarshalPrivateKey(issuerPrivateKeyBytes)
	require.NoError(t, err)

	issuerPublicKeyBytes, err := issuerPrivateKey.PublicKey().Marshal()
	require.NoError(t, err)

	holderPrivateKey, err := bbs.UnmarshalPrivateKey(holderPrivateKeyByets)
	require.NoError(t, err)

	// issuer create a nonce
	nonce := []byte("nonce")

	// issuer create signature suite
	issuerBbsSuite := bbsblssignature2020.NewBBSSuite(issuerPrivateKey, false)
	require.NotNil(t, issuerBbsSuite)

	// holder create suites
	holderBbspsuite := bbsblssignatureproof2020.NewBBSPSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbspsuite)
	holderBbsSuite := bbsblssignature2020.NewBBSSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbsSuite)

	// holder load completed VC and reveal (not secret) VC
	completed := credential.NewCredential()
	err = completed.FromBytes([]byte(vcDoc))
	require.NoError(t, err)
	reveal := credential.NewCredential()
	err = reveal.FromBytes([]byte(revealDocForBlind))
	require.NoError(t, err)

	// holder create builder

	holderBuilder := builder.NewVCBuilder(completed, processor.WithValidateRDF())
	require.NotNil(t, holderBuilder)
	holderBuilder.AddSuite(holderBbspsuite)
	holderBuilder.AddSuite(holderBbsSuite)
	created := new(utils.FormatedTime)
	created.UnmarshalJSON([]byte("2019-12-03T12:19:52Z"))
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
		Created:                 created,
	}

	// holder do create blind signature context with nonce
	ctx, err := holderBuilder.PreBlindSign(reveal, ldpContext, issuerPublicKeyBytes, nonce, processor.WithValidateRDF())
	require.NoError(t, err)
	require.NotNil(t, ctx)

	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(reveal, processor.WithValidateRDF())
	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(issuerBbsSuite)

	// issuer do blind sign with ctx and holder's public key
	blidSig, err := issuerBuilder.BlindSign(
		ctx.ToBytes(),
		holderBbsSuite.RevealedIndexs(),
		holderBbsSuite.MessageCount(),
		ldpContext,
		nonce,
		processor.WithValidateRDF())

	require.NoError(t, err)
	require.NotNil(t, blidSig)

	// holder complete signature
	sigDoc, err := holderBuilder.CompleteSignture(ldpContext, blidSig)
	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	// holder verify signature
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: issuerPublicKeyBytes, Type: "Bls12381G2Key2020"}, nil)
	err = holderBuilder.Verify(resolver, nonce)
	require.NoError(t, err)

	// holder load revealed VC
	rev := credential.NewCredential()
	err = rev.FromBytes([]byte(revealDocForBlindAndDisclu))
	require.NoError(t, err)

	// holder create selective disclouser with issuer's public key
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(rev, &suite.PublicKey{Value: issuerPublicKeyBytes, Type: "Bls12381G2Key2020"}, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, disclu.Expired)

	// verify VC with issuer's public key
	verifier := builder.NewVCBuilder(disclu, processor.WithValidateRDF())
	verifier.AddSuite(bbsblssignatureproof2020.NewBBSPSuite(nil, false))
	err = verifier.Verify(resolver, nonce)
	require.NoError(t, err)
}
