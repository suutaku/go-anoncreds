package builder

import (
	"github.com/suutaku/go-anoncreds/pkg/suite"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
)

const defaultProofPurpose = "assertionMethod"

type VCBuilder struct {
	signatureSuite map[string]suite.SignatureSuite
	credential     *credential.Credential
	processor      *processor.JsonLDProcesser
}
