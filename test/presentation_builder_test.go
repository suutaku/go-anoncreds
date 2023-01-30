package test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"gitee.com/cotnetwork/dids/pkg/dids"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"github.com/suutaku/go-anoncreds/pkg/builder"
	keyresolver "github.com/suutaku/go-anoncreds/pkg/key-resolver"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/presentation"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/utils"
	"github.com/suutaku/ld-loader/pkg/loader"
	"github.com/suutaku/ld-loader/pkg/storage"
)

func TestPresentationBuilder(t *testing.T) {
	// create a custom loader
	defaultLoader := ld.NewDefaultDocumentLoader(http.DefaultClient)
	dLoader := loader.NewCachingDocumentLoader(defaultLoader, storage.LocalKVStorageType)
	privBs, err := base64.RawStdEncoding.DecodeString("IVFeFoIdLHWs2jRFmwKq+HgbR9MczIg2EojhNeaEWQc")
	require.NoError(t, err)
	priv, err := bbs.UnmarshalPrivateKey(privBs)
	require.NoError(t, err)
	require.NotNil(t, priv)
	pub := priv.PublicKey()
	require.NotNil(t, pub)
	bbsSuite := bbsblssignature2020.NewBBSSuite(priv, false)
	require.NotNil(t, bbsSuite)
	t.Log("holder create PR builder")
	prese := presentation.NewPresentation()
	cred := credential.NewCredential()
	cred.FromBytes([]byte(vcDoc))
	prese.Credential = append(prese.Credential, *cred)

	prBuilder := builder.NewPRBuilder(
		prese,
		processor.WithValidateRDF(),
		processor.WithDocumentLoader(dLoader),
	)

	require.NotNil(t, prBuilder)
	prBuilder.AddSuite(bbsSuite)

	t.Log("issuer sign credential")
	// issuer sign credential
	created := new(utils.FormatedTime)
	created.UnmarshalJSON([]byte("2019-12-03T12:19:52Z"))
	did := dids.NewDID(pub)
	ldpContext := &proof.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: proof.SignatureProofValue,
		VerificationMethod:      did.String(),
		Created:                 created,
	}
	sigDoc, err := prBuilder.AddLinkedDataProof(
		ldpContext,
		processor.WithDocumentLoader(dLoader),
	)
	require.NoError(t, err)
	sigPr, ok := sigDoc.(*presentation.Presentation)
	require.True(t, ok)

	t.Logf("%s\n", sigPr.ToBytes())

	require.NoError(t, err)
	require.NotNil(t, sigDoc)
	pubBs, err := priv.PublicKey().Marshal()
	require.NoError(t, err)
	resolver := keyresolver.NewTestPublicKeyResolver(
		&keyresolver.PublicKey{
			Value: pubBs,
			Type:  "Bls12381G2Key2020",
		},
		nil)
	err = prBuilder.Verify(
		resolver,
		processor.WithDocumentLoader(dLoader),
	)

	require.NoError(t, err)

}
