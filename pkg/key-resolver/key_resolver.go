package resolver

import (
	"bytes"
	"crypto"
)

type PublicKey struct {
	Type  string
	Value []byte
	Jwk   []byte
}

func (pbk *PublicKey) Equal(x crypto.PublicKey) bool {
	pbkc, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	if pbkc.Type != pbk.Type {
		return false
	}
	return bytes.Equal(pbkc.Value, pbk.Value) && bytes.Equal(pbkc.Jwk, pbk.Jwk)

}

// PublicKeyResolver resolve publick key value and type, return a PublicKey
type PublicKeyResolver interface {
	Resolve(id string) *PublicKey
}
