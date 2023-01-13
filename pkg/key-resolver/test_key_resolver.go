package resolver

type TestPublicKeyResolver struct {
	pubKey   *PublicKey
	variants map[string]*PublicKey
}

func NewTestPublicKeyResolver(pub *PublicKey, variants map[string]*PublicKey) *TestPublicKeyResolver {
	return &TestPublicKeyResolver{
		pubKey:   pub,
		variants: variants,
	}
}

func (pkrsv *TestPublicKeyResolver) Resolve(id string) *PublicKey {
	if len(pkrsv.variants) > 0 {
		return pkrsv.variants[id]
	}

	return pkrsv.pubKey
}
