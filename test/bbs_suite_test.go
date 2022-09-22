package test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-anoncreds/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-anoncreds/pkg/vc"
)

func TestSuite(t *testing.T) {
	pkBase64 := "h/rkcTKXXzRbOPr9UxSfegCbid2U/cVNXQUaKeGF7UhwrMJFP70uMH0VQ9+3+/2zDPAAjflsdeLkOXW3+ShktLxuPy8UlXSNgKNmkfb+rrj+FRwbs13pv/WsIf+eV66+"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)
	// pkBytes = append(pkBytes, byte('a'))
	bbsSuite := bbsblssignature2020.NewBBSSuite(bbsblssignature2020.NewBBSVerifier(), nil, true)
	//bbsSuite.Verify([]byte(vcDoc), suite.PublicKey{Type: bbsblssignature2020.SignatureType, Value: pkBytes})
	cred := vc.NewCredential()
	cred.Parse([]byte(vcDoc))
	resolver := suite.NewPublicKeyResolver(&suite.PublicKey{Value: pkBytes, Type: "BbsBlsSignature2020"}, nil)
	builder := vc.NewVCBuilder()
	builder.AddSuite(bbsSuite)
	err = builder.Verify(cred, resolver)
	require.NoError(t, err)
}
