// this file contains things related to itsdangerous compatability

package goalone

const (
	// ItsDangerousEpoch is the default epoch used by It's Dangerous
	ItsDangerousEpoch = 1293840000
	// ItsDangerousDerivation is the default Derivation used by It's Dangerous
	ItsDangerousDerivation = `django-concat`
)

var (
	// ItsDangerousSignerSalt is the default salt used by the It's Dangerous
	// "Signer" signer
	ItsDangerousSignerSalt = []byte(`itsdangerous.Signer`)
	// ItsDangerousSerializerSalt is the default salt used by the It's Dangerous
	// "Serializer" and "URLSafeSerializer" signers
	ItsDangerousSerializerSalt = []byte(`itsdangerous`)
)
