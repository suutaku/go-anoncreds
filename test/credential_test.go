package test

import (
	"encoding/json"
	"testing"

	"github.com/suutaku/go-anoncreds/pkg/credential"
)

// go test -v -run ^TestCredentail$ github.com/suutaku/go-anoncreds/test

func TestCredentail(t *testing.T) {
	cred := credential.NewCredential()
	cred.Parse([]byte(vcDoc))
	b := cred.Bytes()

	check := make(map[string]interface{})
	json.Unmarshal([]byte(vcDoc), &check)
	b2, _ := json.Marshal(check)

	t.Logf("%s\n", b)
	t.Logf("%s\n", b2)

	//require.Equal(t, b2, b, "not equal")
}
