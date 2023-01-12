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

func TestSignAndDisclosure(t *testing.T) {
	// issuer load example credential
	cred := credential.NewCredential()
	err := cred.FromBytes([]byte(vcDoc))
	require.NoError(t, err)

	// issuer generate issuer keypair
	pub, priv, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	// issuer create signature suite
	bbsSuite := bbsblssignature2020.NewBBSSuite(priv, false)
	require.NotNil(t, bbsSuite)

	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(bbsSuite)

	// issuer sign credential
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
	}
	sigDoc, err := issuerBuilder.AddLinkedDataProof(ldpContext)
	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	// issuer verify with public key
	pubBytes, err := pub.Marshal()
	require.NoError(t, err)

	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: pubBytes, Type: "Bls12381G2Key2020"}, nil)
	err = issuerBuilder.Verify(resolver, nil)
	require.NoError(t, err)

	// holder generate holder keypair
	_, privH, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	// holder create suite
	holderBbspsuite := bbsblssignatureproof2020.NewBBSPSuite(privH, false)
	require.NotNil(t, holderBbspsuite)
	holderBbsSuite := bbsblssignature2020.NewBBSSuite(privH, false)
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
	nonce := []byte("TestSignAndDisclosure")
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(rev, &suite.PublicKey{Value: pubBytes, Type: "Bls12381G2Key2020"}, nonce)
	require.NoError(t, err)
	require.Empty(t, disclu.Issued)
	require.NotEmpty(t, disclu.Expired)

	// verify VC with issuer's public key
	err = holderBuilder.Verify(resolver, nonce)
	require.NoError(t, err)

}

func TestBlindSignAndDisclosure(t *testing.T) {

	// issuer load example credential
	cred := credential.NewCredential()
	err := cred.FromBytes([]byte(shouldNotBlindJSON))
	require.NoError(t, err)

	// issuer generate issuer keypair
	pub, priv, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	// issuer create signature suite
	bbsSuite := bbsblssignature2020.NewBBSSuite(priv, false)
	require.NotNil(t, bbsSuite)

	// issuer create a nonce
	nonce := []byte("issuer created nonce")

	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(cred, processor.WithValidateRDF())
	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(bbsSuite)

	// holder generate holder keypair
	pubH, privH, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	// holder create suites
	holderBbspsuite := bbsblssignatureproof2020.NewBBSPSuite(privH, false)
	require.NotNil(t, holderBbspsuite)
	holderBbsSuite := bbsblssignature2020.NewBBSSuite(privH, false)
	require.NotNil(t, holderBbsSuite)

	// holder load completed VC and secret VC
	completed := credential.NewCredential()
	err = completed.FromBytes([]byte(vcDoc))
	require.NoError(t, err)
	secret := credential.NewCredential()
	err = secret.FromBytes([]byte(shouldBlindJSON))
	require.NoError(t, err)

	// holder create builder

	holderBuilder := builder.NewVCBuilder(completed, processor.WithValidateRDF())
	require.NotNil(t, holderBuilder)
	holderBuilder.AddSuite(holderBbspsuite)
	holderBuilder.AddSuite(holderBbsSuite)

	// holder do create blind signature context with nonce
	ctx, err := holderBuilder.PreBlindSign(secret, nonce, processor.WithValidateRDF())
	require.NoError(t, err)
	require.NotNil(t, ctx)

	// issuer do blind sign with ctx and holder's public key
	pubHBytes, err := pubH.Marshal()
	require.NoError(t, err)
	blidSig, err := issuerBuilder.BlindSign(ctx.ToBytes(), holderBbsSuite.RevealedIndexs(), holderBbsSuite.MessageCount(), pubHBytes, nonce)
	require.NoError(t, err)
	require.NotNil(t, blidSig)

	// holder complete signature
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
	}
	sigDoc, err := holderBuilder.CompleteSignture(ldpContext, blidSig)
	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	// holder verify signature
	issuerPubBytes, err := pub.Marshal()
	require.NoError(t, err)
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: issuerPubBytes, Type: "Bls12381G2Key2020"}, nil)
	err = holderBuilder.Verify(resolver, nonce)
	require.NoError(t, err)

	// holder load revealed VC
	rev := credential.NewCredential()
	err = rev.FromBytes([]byte(revealJSON))
	require.NoError(t, err)

	// holder create selective disclouser with issuer's public key
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(rev, &suite.PublicKey{Value: issuerPubBytes, Type: "Bls12381G2Key2020"}, nonce)
	require.NoError(t, err)
	require.Empty(t, disclu.Issued)
	require.NotEmpty(t, disclu.Expired)

	// verify VC with issuer's public key
	resolver2 := suite.NewPublicKeyResolver(&suite.PublicKey{Value: issuerPubBytes, Type: "Bls12381G2Key2020"}, nil)
	err = holderBuilder.Verify(resolver2, nonce)
	require.NoError(t, err)
}
