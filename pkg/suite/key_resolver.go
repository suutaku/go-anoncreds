package suite

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
	if bytes.Compare(pbkc.Value, pbk.Value) != 0 {
		return false
	}
	if bytes.Compare(pbkc.Jwk, pbk.Jwk) != 0 {
		return false
	}
	return true
}

type PublicKeyResolver struct {
	pubKey   *PublicKey
	variants map[string]*PublicKey
}

func NewPublicKeyResolver(pub *PublicKey, variants map[string]*PublicKey) *PublicKeyResolver {
	return &PublicKeyResolver{
		pubKey:   pub,
		variants: variants,
	}
}

func (pkrsv *PublicKeyResolver) Resolve(id string) *PublicKey {
	if len(pkrsv.variants) > 0 {
		return pkrsv.variants[id]
	}

	return pkrsv.pubKey
}
