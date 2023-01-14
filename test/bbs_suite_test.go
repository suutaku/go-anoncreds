package test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/suutaku/go-anoncreds/pkg/builder"
	keyresolver "github.com/suutaku/go-anoncreds/pkg/key-resolver"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignatureproof2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/utils"
	"github.com/suutaku/ld-loader/pkg/loader"
	"github.com/suutaku/ld-loader/pkg/storage"
)

func TestSignAndDisclosure(t *testing.T) {

	// create a custom loader
	defaultLoader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	dLoader := loader.NewCachingDocumentLoader(defaultLoader, storage.LocalKVStorageType)

	// issuer load example credential
	cred := credential.NewCredential()
	err := cred.FromBytes([]byte(vcDoc))
	require.NoError(t, err)

	// issuer and holder key pair
	issuerPublicKey, issuerPrivateKey, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	issuerPublicKeyBytes, err := issuerPublicKey.Marshal()
	require.NoError(t, err)

	_, holderPrivateKey, err := bbs.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	// issuer create signature suite
	bbsSuite := bbsblssignature2020.NewBBSSuite(issuerPrivateKey, false)
	require.NotNil(t, bbsSuite)
	t.Log("issuer create VC builder")
	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(
		cred,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader),
	)

	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(bbsSuite)

	t.Log("issuer sign credential")
	// issuer sign credential
	created := new(utils.FormatedTime)
	created.UnmarshalJSON([]byte("2019-12-03T12:19:52Z"))
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      "did:example:123456#key1",
		Created:                 created,
	}
	sigDoc, err := issuerBuilder.AddLinkedDataProof(
		ldpContext,
		processor.WithDocumentLoader(dLoader),
	)

	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	t.Log("issuer verify with public key")
	// issuer verify with public key
	resolver := keyresolver.NewTestPublicKeyResolver(
		&keyresolver.PublicKey{
			Value: issuerPublicKeyBytes,
			Type:  "Bls12381G2Key2020",
		},
		nil)
	err = issuerBuilder.Verify(
		resolver,
		[]byte("nonce"),
		processor.WithDocumentLoader(dLoader),
	)

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

	t.Log(" holder create builder")
	// holder create builder
	holderBuilder := builder.NewVCBuilder(
		cred,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader),
	)

	holderBuilder.AddSuite(holderBbspsuite)
	holderBuilder.AddSuite(holderBbsSuite)

	t.Log("holder create selective disclouser with public key")
	// holder create selective disclouser with public key
	nonce := []byte("nonce")
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(
		rev,
		&keyresolver.PublicKey{
			Value: issuerPublicKeyBytes,
			Type:  "Bls12381G2Key2020",
		},
		nonce,
		processor.WithDocumentLoader(dLoader),
	)
	require.NoError(t, err)
	require.Empty(t, disclu.Issued)
	require.NotEmpty(t, disclu.Expired)

	t.Log("verifier verify VC with issuer's public key")
	// verifier verify VC with issuer's public key
	verifier := builder.NewVCBuilder(
		disclu,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader),
	)

	verifier.AddSuite(bbsblssignatureproof2020.NewBBSPSuite(nil, false))
	err = verifier.Verify(
		resolver,
		nonce,
		processor.WithDocumentLoader(dLoader),
	)

	require.NoError(t, err)
}

func TestBlindSignAndDisclosure(t *testing.T) {

	// create a custom loader
	defaultLoader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	dLoader := loader.NewCachingDocumentLoader(defaultLoader, storage.LocalKVStorageType)

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

	t.Log("holder create suites")
	// holder create suites
	holderBbspsuite := bbsblssignatureproof2020.NewBBSPSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbspsuite)
	holderBbsSuite := bbsblssignature2020.NewBBSSuite(holderPrivateKey, false)
	require.NotNil(t, holderBbsSuite)

	t.Log("holder load completed VC and reveal (not secret) VC")
	// holder load completed VC and reveal (not secret) VC
	completed := credential.NewCredential()
	err = completed.FromBytes([]byte(vcDoc))
	require.NoError(t, err)
	reveal := credential.NewCredential()
	err = reveal.FromBytes([]byte(revealDocForBlind))
	require.NoError(t, err)

	t.Log("holder create builder")
	// holder create builder
	holderBuilder := builder.NewVCBuilder(
		completed,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader))

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

	t.Log("holder do create blind signature context with nonce")
	// holder do create blind signature context with nonce
	ctx, err := holderBuilder.PreBlindSign(
		reveal,
		ldpContext,
		issuerPublicKeyBytes,
		nonce,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader))

	require.NoError(t, err)
	require.NotNil(t, ctx)

	t.Log("issuer create VC builder")
	// issuer create VC builder
	issuerBuilder := builder.NewVCBuilder(
		reveal,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader))

	require.NotNil(t, issuerBuilder)
	issuerBuilder.AddSuite(issuerBbsSuite)

	t.Log("issuer do blind sign with ctx and holder's public key")
	// issuer do blind sign with ctx and holder's public key
	blidSig, err := issuerBuilder.BlindSign(
		ctx.ToBytes(),
		holderBbsSuite.RevealedIndexs(),
		holderBbsSuite.MessageCount(),
		ldpContext,
		nonce,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader))

	require.NoError(t, err)
	require.NotNil(t, blidSig)

	t.Log("holder complete signature")
	// holder complete signature
	sigDoc, err := holderBuilder.CompleteSignture(ldpContext, blidSig)
	require.NoError(t, err)
	require.NotNil(t, sigDoc)

	t.Log("holder verify signature")
	// holder verify signature
	resolver := keyresolver.NewTestPublicKeyResolver(&keyresolver.PublicKey{Value: issuerPublicKeyBytes, Type: "Bls12381G2Key2020"}, nil)
	err = holderBuilder.Verify(
		resolver,
		nonce,
		processor.WithDocumentLoader(dLoader))

	require.NoError(t, err)

	// holder load revealed VC
	rev := credential.NewCredential()
	err = rev.FromBytes([]byte(revealDocForBlindAndDisclu))
	require.NoError(t, err)

	t.Log("holder create selective disclouser with issuer's public key")
	// holder create selective disclouser with issuer's public key
	disclu, err := holderBuilder.GenerateBBSSelectiveDisclosure(
		rev,
		&keyresolver.PublicKey{
			Value: issuerPublicKeyBytes,
			Type:  "Bls12381G2Key2020"},
		nonce,
		processor.WithDocumentLoader(dLoader))

	require.NoError(t, err)
	require.NotEmpty(t, disclu.Expired)

	t.Log("verify VC with issuer's public key")
	// verify VC with issuer's public key
	verifier := builder.NewVCBuilder(
		disclu,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader),
	)
	verifier.AddSuite(bbsblssignatureproof2020.NewBBSPSuite(nil, false))
	err = verifier.Verify(
		resolver,
		nonce,
		processor.WithDocumentLoader(dLoader),
	)
	require.NoError(t, err)
}
