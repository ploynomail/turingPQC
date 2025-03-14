// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"time"
	"unicode"

	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	falcon1024 "github.com/ploynomail/turingPQC/pqc/falcon/falcon1024"
	falcon512 "github.com/ploynomail/turingPQC/pqc/falcon/falcon512"
	"github.com/ploynomail/turingPQC/sm2"
	sm2dilithium2hybrid "github.com/ploynomail/turingPQC/sm2_dilithium2_hybrid"
	"github.com/ploynomail/turingPQC/sm3"

	dilithium2 "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium2"
	dilithium2AES "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium2AES"
	dilithium3 "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium3"
	dilithium3AES "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium3AES"
	dilithium5 "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium5"
	dilithium5AES "github.com/ploynomail/turingPQC/pqc/dilithium/dilithium5AES"

	rainbowIIICircumzenithal "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowIIICircumzenithal"
	rainbowIIIClassic "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowIIIClassic"
	rainbowIIICompressed "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowIIICompressed"
	rainbowVCircumzenithal "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowVCircumzenithal"
	rainbowVClassic "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowVClassic"
	rainbowVCompressed "github.com/ploynomail/turingPQC/pqc/rainbow/rainbowVCompressed"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type Hash uint

const (
	MD4        Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                        // import crypto/md5
	SHA1                       // import crypto/sha1
	SHA224                     // import crypto/sha256
	SHA256                     // import crypto/sha256
	SHA384                     // import crypto/sha512
	SHA512                     // import crypto/sha512
	MD5SHA1                    // no implementation; MD5+SHA1 used for TLS RSA
	RIPEMD160                  // import golang.org/x/crypto/ripemd160
	SHA3_224                   // import golang.org/x/crypto/sha3
	SHA3_256                   // import golang.org/x/crypto/sha3
	SHA3_384                   // import golang.org/x/crypto/sha3
	SHA3_512                   // import golang.org/x/crypto/sha3
	SHA512_224                 // import crypto/sha512
	SHA512_256                 // import crypto/sha512
	SM3
	maxHash
)

var digestSizes = []uint8{
	MD4:        16,
	MD5:        16,
	SHA1:       20,
	SHA224:     28,
	SHA256:     32,
	SHA384:     48,
	SHA512:     64,
	SHA512_224: 28,
	SHA512_256: 32,
	SHA3_224:   28,
	SHA3_256:   32,
	SHA3_384:   48,
	SHA3_512:   64,
	MD5SHA1:    36,
	RIPEMD160:  20,
	SM3:        32,
}

func init() {
	RegisterHash(MD4, nil)
	RegisterHash(MD5, md5.New)
	RegisterHash(SHA1, sha1.New)
	RegisterHash(SHA224, sha256.New224)
	RegisterHash(SHA256, sha256.New)
	RegisterHash(SHA384, sha512.New384)
	RegisterHash(SHA512, sha512.New)
	RegisterHash(MD5SHA1, nil)
	RegisterHash(RIPEMD160, ripemd160.New)
	RegisterHash(SHA3_224, sha3.New224)
	RegisterHash(SHA3_256, sha3.New256)
	RegisterHash(SHA3_384, sha3.New384)
	RegisterHash(SHA3_512, sha3.New512)
	RegisterHash(SHA512_224, sha512.New512_224)
	RegisterHash(SHA512_256, sha512.New512_256)
	RegisterHash(SM3, sm3.New)
}

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() crypto.Hash {
	return crypto.Hash(h)
}

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 && h < maxHash {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

var hashes = make([]func() hash.Hash, maxHash)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return h < maxHash && hashes[h] != nil
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or
// ed25519.PublicKey. More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}
	return parsePublicKey(algo, &pki)
}

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519

	case *falcon512.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyFalcon512
	case *falcon1024.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyFalcon1024

	case *dilithium2.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium2
	case *dilithium3.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium3
	case *dilithium5.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium5
	case *dilithium2AES.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium2AES
	case *dilithium3AES.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium3AES
	case *dilithium5AES.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyDilithium5AES

	case *rainbowIIIClassic.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowIIIClassic
	case *rainbowIIICircumzenithal.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowIIICircumzenithal
	case *rainbowIIICompressed.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowIIICompressed
	case *rainbowVClassic.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowVClassic
	case *rainbowVCircumzenithal.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowVCircumzenithal
	case *rainbowVCompressed.PublicKey:
		publicKeyBytes = pub.Pk
		publicKeyAlgorithm.Algorithm = oidPublicKeyRainbowVCompressed
	case *sm2.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported SM2 curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case *sm2dilithium2hybrid.PublicKey:
		dilithium2PubKeyBytes := pub.Dilithium2PublicKey.Pk
		sm2PubKeyBytes := elliptic.Marshal(pub.SM2PublicKey.Curve, pub.SM2PublicKey.X, pub.SM2PublicKey.Y)
		publicKeyBytes = append(sm2PubKeyBytes, dilithium2PubKeyBytes...)
		oidBytes, _ := asn1.Marshal(oidPublicKeySm2Dilithium2Hybrid)
		publicKeyAlgorithm.Algorithm = oidPublicKeySm2Hybrid
		publicKeyAlgorithm.Parameters = asn1.RawValue{
			FullBytes: oidBytes,
		}
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// The following key types are currently supported: *rsa.PublicKey, *ecdsa.PublicKey
// and ed25519.PublicKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota

	MD2WithRSA // Unsupported.
	MD5WithRSA // Only supported for signing, not verification.
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1   // Unsupported.
	DSAWithSHA256 // Unsupported.
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	PureEd25519

	PureFalcon512
	PureFalcon1024

	PureDilithium2
	PureDilithium3
	PureDilithium5
	PureDilithium2AES
	PureDilithium3AES
	PureDilithium5AES

	PureRainbowIIIClassic
	PureRainbowIIICircumzenithal
	PureRainbowIIICompressed
	PureRainbowVClassic
	PureRainbowVCircumzenithal
	PureRainbowVCompressed
	SM2WithSM3
	SM2WithSHA1
	SM2WithSHA256
	PureSm2Hybrid
	PureSM2Dilithium2Hybrid
)

func (algo SignatureAlgorithm) isRSAPSS() bool {
	switch algo {
	case SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

func (algo SignatureAlgorithm) String() string {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.name
		}
	}
	return strconv.Itoa(int(algo))
}

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA // Unsupported.
	ECDSA
	Ed25519

	Falcon512
	Falcon1024

	Dilithium2
	Dilithium3
	Dilithium5
	Dilithium2AES
	Dilithium3AES
	Dilithium5AES

	RainbowIIIClassic
	RainbowIIICircumzenithal
	RainbowIIICompressed
	RainbowVClassic
	RainbowVCircumzenithal
	RainbowVCompressed
	Sm2
	Sm2Hybrid
	Sm2Dilithium2Hybrid
)

var publicKeyAlgoName = [...]string{
	RSA:     "RSA",
	DSA:     "DSA",
	ECDSA:   "ECDSA",
	Ed25519: "Ed25519",

	Falcon512:  "falcon512",
	Falcon1024: "Falcon1024",

	Dilithium2:    "Dilithium2",
	Dilithium3:    "Dilithium3",
	Dilithium5:    "Dilithium5",
	Dilithium2AES: "Dilithium2AES",
	Dilithium3AES: "Dilithium3AES",
	Dilithium5AES: "Dilithium5AES",

	RainbowIIIClassic:        "RainbowIIIClassic",
	RainbowIIICircumzenithal: "RainbowIIICircumzenithal",
	RainbowIIICompressed:     "RainbowIIICompressed",
	RainbowVClassic:          "RainbowVClassic",
	RainbowVCircumzenithal:   "RainbowVCircumzenithal",
	RainbowVCompressed:       "RainbowVCompressed",
	SM2WithSM3:               "SM2-SM3",
	SM2WithSHA1:              "SM2-SHA1",
	SM2WithSHA256:            "SM2-SHA256",
	Sm2Hybrid:                "SM2-Hybrid",
	Sm2Dilithium2Hybrid:      "SM2-Dilithium2-Hybrid",
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// OIDs for signature algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
// md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
// md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
// sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
// dsaWithSha1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
// ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
// 	  iso(1) member-body(2) us(840) ansi-x962(10045)
//    signatures(4) ecdsa-with-SHA1(1)}
//
//
// RFC 4055 5 PKCS #1 Version 1.5
//
// sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
// sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
//
// RFC 5758 3.1 DSA Signature Algorithms
//
// dsaWithSha256 OBJECT IDENTIFIER ::= {
//    joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//    csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
// id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSignatureFalcon512  = asn1.ObjectIdentifier{1, 1, 0, 0} // function, security leveal, algorithm name, count
	oidSignatureFalcon1024 = asn1.ObjectIdentifier{1, 5, 0, 1}

	oidSignatureDilithium2    = asn1.ObjectIdentifier{1, 2, 1, 0}
	oidSignatureDilithium3    = asn1.ObjectIdentifier{1, 3, 1, 1}
	oidSignatureDilithium5    = asn1.ObjectIdentifier{1, 5, 1, 2}
	oidSignatureDilithium2AES = asn1.ObjectIdentifier{1, 2, 1, 3}
	oidSignatureDilithium3AES = asn1.ObjectIdentifier{1, 3, 1, 4}
	oidSignatureDilithium5AES = asn1.ObjectIdentifier{1, 5, 1, 5}

	oidSignatureRainbowIIIClassic        = asn1.ObjectIdentifier{1, 3, 2, 3}
	oidSignatureRainbowIIICircumzenithal = asn1.ObjectIdentifier{1, 3, 2, 4}
	oidSignatureRainbowIIICompressed     = asn1.ObjectIdentifier{1, 3, 2, 5}
	oidSignatureRainbowVClassic          = asn1.ObjectIdentifier{1, 5, 2, 6}
	oidSignatureRainbowVCircumzenithal   = asn1.ObjectIdentifier{1, 5, 2, 7}
	oidSignatureRainbowVCompressed       = asn1.ObjectIdentifier{1, 5, 2, 8}

	oidSignatureSM2WithSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSignatureSM2WithSHA1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	oidSignatureSM2WithSHA256 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
	//	oidSignatureSM3WithRSA      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}

	oidSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
	oidSignatureSm2Hybrid           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 800}
	oidSignatureSm2Dilithium2Hybrid = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 800, 1, 1}
)

var signatureAlgorithmDetails = []struct {
	algo       SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo PublicKeyAlgorithm
	hash       Hash
}{
	{MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, RSA, Hash(0) /* no value for MD2 */},
	{MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, RSA, MD5},
	{SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, RSA, SHA1},
	{SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, RSA, SHA1},
	{SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, RSA, SHA256},
	{SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, RSA, SHA384},
	{SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, RSA, SHA512},
	{SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, RSA, SHA256},
	{SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, RSA, SHA384},
	{SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, RSA, SHA512},
	{DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1},
	{DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256},
	{ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1},
	{ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256},
	{ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384},
	{ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512},
	{PureEd25519, "Ed25519", oidSignatureEd25519, Ed25519, Hash(0) /* no pre-hashing */},

	{PureFalcon512, "falcon512", oidSignatureFalcon512, Falcon512, Hash(0)},
	{PureFalcon1024, "Falcon1024", oidSignatureFalcon1024, Falcon1024, Hash(0)},

	{PureDilithium2, "Dilithium2", oidSignatureDilithium2, Dilithium2, Hash(0)},
	{PureDilithium3, "Dilithium3", oidSignatureDilithium3, Dilithium3, Hash(0)},
	{PureDilithium5, "Dilithium5", oidSignatureDilithium5, Dilithium5, Hash(0)},
	{PureDilithium2AES, "Dilithium2AES", oidSignatureDilithium2AES, Dilithium2AES, Hash(0)},
	{PureDilithium3AES, "Dilithium3AES", oidSignatureDilithium3AES, Dilithium3AES, Hash(0)},
	{PureDilithium5AES, "Dilithium5AES", oidSignatureDilithium5AES, Dilithium5AES, Hash(0)},

	{PureRainbowIIIClassic, "RainbowIIIClassic", oidSignatureRainbowIIIClassic, RainbowIIIClassic, Hash(0)},
	{PureRainbowIIICircumzenithal, "RainbowIIICircumzenithal", oidSignatureRainbowIIICircumzenithal, RainbowIIICircumzenithal, Hash(0)},
	{PureRainbowIIICompressed, "RainbowIIICompressed", oidSignatureRainbowIIICompressed, RainbowIIICompressed, Hash(0)},
	{PureRainbowVClassic, "RainbowVClassic", oidSignatureRainbowVClassic, RainbowVClassic, Hash(0)},
	{PureRainbowVCircumzenithal, "RainbowVCircumzenithal", oidSignatureRainbowVCircumzenithal, RainbowVCircumzenithal, Hash(0)},
	{PureRainbowVCompressed, "RainbowVCompressed", oidSignatureRainbowVCompressed, RainbowVCompressed, Hash(0)},
	{SM2WithSM3, "SM2-SM3", oidSignatureSM2WithSM3, ECDSA, Hash(0)},
	{SM2WithSHA1, "SM2-SHA1", oidSignatureSM2WithSHA1, Sm2, SHA1},
	{SM2WithSHA256, "SM2-SHA256", oidSignatureSM2WithSHA256, Sm2, SHA256},
	{PureSm2Hybrid, "SM2-Hybrid", oidSignatureSm2Hybrid, Sm2Hybrid, Hash(0)},
	{PureSM2Dilithium2Hybrid, "SM2-Dilithium2-Hybrid", oidSignatureSm2Dilithium2Hybrid, Sm2Dilithium2Hybrid, Hash(0)},
	//	{SM3WithRSA, oidSignatureSM3WithRSA, RSA, SM3},
}

// hashToPSSParameters contains the DER encoded RSA PSS parameters for the
// SHA256, SHA384, and SHA512 hashes as defined in RFC 3447, Appendix A.2.3.
// The parameters contain the following values:
//   - hashAlgorithm contains the associated hash identifier with NULL parameters
//   - maskGenAlgorithm always contains the default mgf1SHA1 identifier
//   - saltLength contains the length of the associated hash
//   - trailerField always contains the default trailerFieldBC value
var hashToPSSParameters = map[Hash]asn1.RawValue{
	SHA256: asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}},
	SHA384: asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}},
	SHA512: asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) SignatureAlgorithm {
	if ai.Algorithm.Equal(oidSignatureSM2WithSM3) {
		return SM2WithSM3
	}
	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return UnknownSignatureAlgorithm
	}
	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		return SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		return SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		return SHA512WithRSAPSS
	}

	return UnknownSignatureAlgorithm
}

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//
//	rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//
//	x9-57(10040) x9cm(4) 1 }
//
// # RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
//	id-ecPublicKey OBJECT IDENTIFIER ::= {
//	      iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = oidSignatureEd25519

	oidPublicKeyFalcon512  = oidSignatureFalcon512
	oidPublicKeyFalcon1024 = oidSignatureFalcon1024

	oidPublicKeyDilithium2    = oidSignatureDilithium2
	oidPublicKeyDilithium3    = oidSignatureDilithium3
	oidPublicKeyDilithium5    = oidSignatureDilithium5
	oidPublicKeyDilithium2AES = oidSignatureDilithium2AES
	oidPublicKeyDilithium3AES = oidSignatureDilithium3AES
	oidPublicKeyDilithium5AES = oidSignatureDilithium5AES

	oidPublicKeyRainbowIIIClassic        = oidSignatureRainbowIIIClassic
	oidPublicKeyRainbowIIICircumzenithal = oidSignatureRainbowIIICircumzenithal
	oidPublicKeyRainbowIIICompressed     = oidSignatureRainbowIIICompressed
	oidPublicKeyRainbowVClassic          = oidSignatureRainbowVClassic
	oidPublicKeyRainbowVCircumzenithal   = oidSignatureRainbowVCircumzenithal
	oidPublicKeyRainbowVCompressed       = oidSignatureRainbowVCompressed
	oidPublicKeySM2                      = oidSignatureSM2WithSM3
	oidPublicKeySm2Hybrid                = oidSignatureSm2Hybrid
	oidPublicKeySm2Dilithium2Hybrid      = oidSignatureSm2Dilithium2Hybrid
)

// 根据oid获取公钥算法
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return RSA
	case oid.Equal(oidPublicKeyDSA):
		return DSA
	case oid.Equal(oidPublicKeyECDSA):
		return ECDSA
	case oid.Equal(oidPublicKeyEd25519):
		return Ed25519

	case oid.Equal(oidPublicKeyFalcon512):
		return Falcon512
	case oid.Equal(oidPublicKeyFalcon1024):
		return Falcon1024
	case oid.Equal(oidPublicKeyDilithium2):
		return Dilithium2
	case oid.Equal(oidPublicKeyDilithium3):
		return Dilithium3
	case oid.Equal(oidPublicKeyDilithium5):
		return Dilithium5
	case oid.Equal(oidPublicKeyDilithium2AES):
		return Dilithium2AES
	case oid.Equal(oidPublicKeyDilithium3AES):
		return Dilithium3AES
	case oid.Equal(oidPublicKeyDilithium5AES):
		return Dilithium5AES
	case oid.Equal(oidPublicKeyRainbowIIIClassic):
		return RainbowIIIClassic
	case oid.Equal(oidPublicKeyRainbowIIICircumzenithal):
		return RainbowIIICircumzenithal
	case oid.Equal(oidPublicKeyRainbowIIICompressed):
		return RainbowIIICompressed
	case oid.Equal(oidPublicKeyRainbowVClassic):
		return RainbowVClassic
	case oid.Equal(oidPublicKeyRainbowVCircumzenithal):
		return RainbowVCircumzenithal
	case oid.Equal(oidPublicKeyRainbowVCompressed):
		return RainbowVCompressed
	case oid.Equal(oidPublicKeySm2Hybrid):
		return Sm2Hybrid
	}
	return UnknownPublicKeyAlgorithm
}

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224    = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301} // I get the SM2 ID through parsing the pem file generated by gmssl

)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveP256SM2):
		return sm2.P256Sm2()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm2.P256Sm2():
		return oidNamedCurveP256SM2, true
	}

	return nil, false
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	// BasicConstraintsValid indicates whether IsCA, MaxPathLen,
	// and MaxPathLenZero are valid.
	BasicConstraintsValid bool
	IsCA                  bool

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values. (Note that these values may not be valid
	// if invalid values were contained within a parsed certificate. For
	// example, an element of DNSNames may not be a valid DNS domain name.)
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// An InsecureAlgorithmError
type InsecureAlgorithmError SignatureAlgorithm

func (e InsecureAlgorithmError) Error() string {
	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", SignatureAlgorithm(e))
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

func (c *Certificate) hasSANExtension() bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	return checkSignature(algo, signed, signature, c.PublicKey)
}

func (c *Certificate) hasNameConstraints() bool {
	return oidInExtensions(oidExtensionNameConstraints, c.Extensions)
}

func (c *Certificate) getSANExtension() []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo PublicKeyAlgorithm, pubKey interface{}) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
}

// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	var hashType Hash
	switch algo {
	case SHA1WithRSA, DSAWithSHA1, ECDSAWithSHA1, SM2WithSHA1:
		hashType = SHA1
	case SHA256WithRSA, SHA256WithRSAPSS, DSAWithSHA256, ECDSAWithSHA256, SM2WithSHA256:
		hashType = SHA256
	case SHA384WithRSA, SHA384WithRSAPSS, ECDSAWithSHA384:
		hashType = SHA384
	case SHA512WithRSA, SHA512WithRSAPSS, ECDSAWithSHA512:
		hashType = SHA512
	case MD2WithRSA, MD5WithRSA:
		return InsecureAlgorithmError(algo)
	case SM2WithSM3: // SM3WithRSA reserve
		hashType = Hash(0)
	case PureSM2Dilithium2Hybrid, PureSm2Hybrid, PureDilithium2:
		hashType = Hash(0)
	default:
		return ErrUnsupportedAlgorithm
	}
	var pubKeyAlgo PublicKeyAlgorithm
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
		}
	}
	switch hashType {
	case Hash(0):
		if pubKeyAlgo != Sm2Dilithium2Hybrid && pubKeyAlgo != ECDSA && pubKeyAlgo != Sm2Hybrid && pubKeyAlgo != Sm2 && pubKeyAlgo != Ed25519 && pubKeyAlgo != Falcon512 && pubKeyAlgo != Falcon1024 && pubKeyAlgo != Dilithium2 && pubKeyAlgo != Dilithium3 && pubKeyAlgo != Dilithium5 && pubKeyAlgo != Dilithium2AES && pubKeyAlgo != Dilithium3AES && pubKeyAlgo != Dilithium5AES && pubKeyAlgo != RainbowIIIClassic && pubKeyAlgo != RainbowIIICircumzenithal && pubKeyAlgo != RainbowIIICompressed && pubKeyAlgo != RainbowVClassic && pubKeyAlgo != RainbowVCircumzenithal && pubKeyAlgo != RainbowVCompressed {
			return ErrUnsupportedAlgorithm
		}
	case MD5:
		return InsecureAlgorithmError(algo)
	default:
		if !hashType.Available() {
			return ErrUnsupportedAlgorithm
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, crypto.Hash(hashType), signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, crypto.Hash(hashType), signed, signature)
		}
	case *ecdsa.PublicKey:
		if pubKeyAlgo != ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		switch pub.Curve {
		case sm2.P256Sm2():
			sm2pub := &sm2.PublicKey{
				Curve: pub.Curve,
				X:     pub.X,
				Y:     pub.Y,
			}
			if !sm2pub.Verify(signed, signature) {
				return errors.New("x509: sm2 verification failure")
			}
		default:
			if !ecdsa.VerifyASN1(pub, signed, signature) {
				return errors.New("x509: ECDSA verification failure")
			}
		}

		return
	case ed25519.PublicKey:
		if pubKeyAlgo != Ed25519 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return errors.New("x509: Ed25519 verification failure")
		}
		return

	case *falcon512.PublicKey:
		if pubKeyAlgo != Falcon512 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !falcon512.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, falcon512")
		}
		return
	case *falcon1024.PublicKey:
		if pubKeyAlgo != Falcon1024 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !falcon1024.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, falcon1024")
		}
		return

	case *dilithium2.PublicKey:
		if pubKeyAlgo != Dilithium2 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium2.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium2")
		}
		return
	case *dilithium3.PublicKey:
		if pubKeyAlgo != Dilithium3 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium3.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium3")
		}
		return
	case *dilithium5.PublicKey:
		if pubKeyAlgo != Dilithium5 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium5.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium5")
		}
		return
	case *dilithium2AES.PublicKey:
		if pubKeyAlgo != Dilithium2AES {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium2AES.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium2AES")
		}
		return
	case *dilithium3AES.PublicKey:
		if pubKeyAlgo != Dilithium3AES {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium3AES.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium3AES")
		}
		return
	case *dilithium5AES.PublicKey:
		if pubKeyAlgo != Dilithium5AES {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !dilithium5AES.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, dilithium5AES")
		}
		return

	case *rainbowIIIClassic.PublicKey:
		if pubKeyAlgo != RainbowIIIClassic {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowIIIClassic.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowIIIClassic")
		}
		return
	case *rainbowIIICircumzenithal.PublicKey:
		if pubKeyAlgo != RainbowIIICircumzenithal {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowIIICircumzenithal.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowIIICircumzenithal")
		}
		return
	case *rainbowIIICompressed.PublicKey:
		if pubKeyAlgo != RainbowIIICompressed {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowIIICompressed.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowIIICompressed")
		}
		return
	case *rainbowVClassic.PublicKey:
		if pubKeyAlgo != RainbowVClassic {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowVClassic.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowVClassic")
		}
		return
	case *rainbowVCircumzenithal.PublicKey:
		if pubKeyAlgo != RainbowVCircumzenithal {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowVCircumzenithal.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowVCircumzenithal")
		}
		return
	case *rainbowVCompressed.PublicKey:
		if pubKeyAlgo != RainbowVCompressed {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !rainbowVCompressed.Verify(pub, signed, signature) {
			return errors.New("x509: pqc verification failure, rainbowVCompressed")
		}
		return
	case *sm2.PublicKey:
		if pubKeyAlgo != ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		switch pub.Curve {
		case sm2.P256Sm2():
			sm2pub := &sm2.PublicKey{
				Curve: pub.Curve,
				X:     pub.X,
				Y:     pub.Y,
			}

			if !sm2pub.Verify(signed, signature) {
				return errors.New("x509: sm2 verification failure")
			}
		}

		return
	case *sm2dilithium2hybrid.PublicKey:
		if pubKeyAlgo != Sm2Hybrid {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		// 由于dilithium2 私钥中没有存储公钥，所以无法直接验证
		// if !sm2dilithium2hybrid.Verify(pub, signed, signature) {
		// 	return errors.New("x509: pqc verification failure, sm2dilithium2hybrid")
		// }
		return
	}
	return ErrUnsupportedAlgorithm
}

// CheckCRLSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	algo := getSignatureAlgorithmFromAI(crl.SignatureAlgorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidNotInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func buildCertExtensions(template *Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalExtKeyUsage(template.ExtKeyUsage, template.UnknownExtKeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		ret[n], err = marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(subjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(subjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// From RFC 5280, Section 4.2.1.6:
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n], err = marshalCertificatePolicies(template.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func marshalKeyUsage(ku KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func marshalExtKeyUsage(extUsages []ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionExtendedKeyUsage}

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, errors.New("x509: unknown extended key usage")
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	var err error
	ext.Value, err = asn1.Marshal(oids)
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true}
	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}
	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	if err != nil {
		return ext, nil
	}
	return ext, nil
}

func marshalCertificatePolicies(policyIdentifiers []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionCertificatePolicies}
	policies := make([]policyInformation, len(policyIdentifiers))
	for i, policy := range policyIdentifiers {
		policies[i].Policy = policy
	}
	var err error
	ext.Value, err = asn1.Marshal(policies)
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func buildCSRExtensions(template *CertificateRequest) ([]pkix.Extension, error) {
	var ret []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	return append(ret, template.ExtraExtensions...), nil
}

func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPublicKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo SignatureAlgorithm) (hashFunc Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = RSA
		hashFunc = SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case *ecdsa.PublicKey:
		pubType = ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	case ed25519.PublicKey:
		pubType = Ed25519
		sigAlgo.Algorithm = oidSignatureEd25519

	case *falcon512.PublicKey:
		pubType = Falcon512
		sigAlgo.Algorithm = oidSignatureFalcon512
	case *falcon1024.PublicKey:
		pubType = Falcon1024
		sigAlgo.Algorithm = oidSignatureFalcon1024

	case *dilithium2.PublicKey:
		pubType = Dilithium2
		sigAlgo.Algorithm = oidSignatureDilithium2
	case *dilithium3.PublicKey:
		pubType = Dilithium3
		sigAlgo.Algorithm = oidSignatureDilithium3
	case *dilithium5.PublicKey:
		pubType = Dilithium5
		sigAlgo.Algorithm = oidSignatureDilithium5
	case *dilithium2AES.PublicKey:
		pubType = Dilithium2AES
		sigAlgo.Algorithm = oidSignatureDilithium2AES
	case *dilithium3AES.PublicKey:
		pubType = Dilithium3AES
		sigAlgo.Algorithm = oidSignatureDilithium3AES
	case *dilithium5AES.PublicKey:
		pubType = Dilithium5AES
		sigAlgo.Algorithm = oidSignatureDilithium5AES

	case *rainbowIIIClassic.PublicKey:
		pubType = RainbowIIIClassic
		sigAlgo.Algorithm = oidSignatureRainbowIIIClassic
	case *rainbowIIICircumzenithal.PublicKey:
		pubType = RainbowIIICircumzenithal
		sigAlgo.Algorithm = oidSignatureRainbowIIICircumzenithal
	case *rainbowIIICompressed.PublicKey:
		pubType = RainbowIIICompressed
		sigAlgo.Algorithm = oidSignatureRainbowIIICompressed
	case *rainbowVClassic.PublicKey:
		pubType = RainbowVClassic
		sigAlgo.Algorithm = oidSignatureRainbowVClassic
	case *rainbowVCircumzenithal.PublicKey:
		pubType = RainbowVCircumzenithal
		sigAlgo.Algorithm = oidSignatureRainbowVCircumzenithal
	case *rainbowVCompressed.PublicKey:
		pubType = RainbowVCompressed
		sigAlgo.Algorithm = oidSignatureRainbowVCompressed
	case *sm2.PublicKey:
		pubType = ECDSA
		switch pub.Curve {
		case sm2.P256Sm2():
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
	case *sm2dilithium2hybrid.PublicKey:
		pubType = Sm2Hybrid
		sigAlgo.Algorithm = oidSignatureSm2Hybrid
		oidBytes, _ := asn1.Marshal(oidSignatureSm2Dilithium2Hybrid)
		rawValue := asn1.RawValue{FullBytes: oidBytes}
		sigAlgo.Parameters = rawValue
	default:
		err = errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 && pubType != Sm2Hybrid && pubType != ECDSA && pubType != Ed25519 && pubType != Falcon512 && pubType != Falcon1024 && pubType != Dilithium2 && pubType != Dilithium3 && pubType != Dilithium5 && pubType != Dilithium2AES && pubType != Dilithium3AES && pubType != Dilithium5AES && pubType != RainbowIIIClassic && pubType != RainbowIIICircumzenithal && pubType != RainbowIIICompressed && pubType != RainbowVClassic && pubType != RainbowVCircumzenithal && pubType != RainbowVCompressed {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			if requestedSigAlgo.isRSAPSS() {
				sigAlgo.Parameters = hashToPSSParameters[hashFunc]
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}
	return
}

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate creates a new X.509 v3 certificate based on a template.
// The following members of template are currently used:
//
//   - AuthorityKeyId
//   - BasicConstraintsValid
//   - CRLDistributionPoints
//   - DNSNames
//   - EmailAddresses
//   - ExcludedDNSDomains
//   - ExcludedEmailAddresses
//   - ExcludedIPRanges
//   - ExcludedURIDomains
//   - ExtKeyUsage
//   - ExtraExtensions
//   - IPAddresses
//   - IsCA
//   - IssuingCertificateURL
//   - KeyUsage
//   - MaxPathLen
//   - MaxPathLenZero
//   - NotAfter
//   - NotBefore
//   - OCSPServer
//   - PermittedDNSDomains
//   - PermittedDNSDomainsCritical
//   - PermittedEmailAddresses
//   - PermittedIPRanges
//   - PermittedURIDomains
//   - PolicyIdentifiers
//   - SerialNumber
//   - SignatureAlgorithm
//   - Subject
//   - SubjectKeyId
//   - URIs
//   - UnknownExtKeyUsage
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// certificate to be generated and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The currently supported key types are *rsa.PublicKey, *ecdsa.PublicKey and
// ed25519.PublicKey. pub must be a supported key type, and priv must be a
// crypto.Signer with a supported public key.
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//
// If SubjectKeyId from template is empty and the template is a CA, SubjectKeyId
// will be generated from the hash of the public key.
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) ([]byte, error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	// Check that the signer's public key matches the private key, if available.
	type privateKey interface {
		Equal(crypto.PublicKey) bool
	}
	if privPub, ok := key.Public().(privateKey); !ok {
		return nil, errors.New("x509: internal error: supported public key does not implement Equal")
	} else if parent.PublicKey != nil && !privPub.Equal(parent.PublicKey) {
		return nil, errors.New("x509: provided PrivateKey doesn't match parent's PublicKey")
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	signed := tbsCertContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}
	var signerOpts crypto.SignerOpts = hashFunc
	if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.Hash(hashFunc),
		}
	}

	var signature []byte
	signature, err = key.Sign(rand, signed, signerOpts)
	if err != nil {
		return nil, err
	}
	signedCert, err := asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, err
	}
	// Check the signature to ensure the crypto.Signer behaved correctly.
	// We skip this check if the signature algorithm is MD5WithRSA as we
	// only support this algorithm for signing, and not verification.
	if sigAlg := getSignatureAlgorithmFromAI(signatureAlgorithm); sigAlg != MD5WithRSA {
		if err := checkSignature(sigAlg, c.Raw, signature, key.Public()); err != nil {
			return nil, fmt.Errorf("x509: signature over certificate returned by signer is invalid: %w", err)
		}
	}
	return signedCert, nil
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
func ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == pemType {
			crlBytes = block.Bytes
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL parses a DER encoded CRL from the given bytes.
func ParseDERCRL(derBytes []byte) (*pkix.CertificateList, error) {
	certList := new(pkix.CertificateList)
	if rest, err := asn1.Unmarshal(derBytes, certList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after CRL")
	}
	return certList, nil
}

// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
// contains the given list of revoked certificates.
//
// Note: this method does not generate an RFC 5280 conformant X.509 v2 CRL.
// To generate a standards compliant CRL, use CreateRevocationList instead.
func (c *Certificate) CreateCRL(rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(key.Public(), 0)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:             1,
		Signature:           signatureAlgorithm,
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCertsUTC,
	}

	// Authority Key Id
	if len(c.SubjectKeyId) > 0 {
		var aki pkix.Extension
		aki.Id = oidExtensionAuthorityKeyId
		aki.Value, err = asn1.Marshal(authKeyId{Id: c.SubjectKeyId})
		if err != nil {
			return
		}
		tbsCertList.Extensions = append(tbsCertList.Extensions, aki)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	signed := tbsCertListContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	var signature []byte
	signature, err = key.Sign(rand, signed, hashFunc)
	if err != nil {
		return
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Subject pkix.Name

	// Attributes contains the CSR attributes that can parse as
	// pkix.AttributeTypeAndValueSET.
	//
	// Deprecated: Use Extensions and ExtraExtensions instead for parsing and
	// generating the requestedExtensions attribute.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains all requested extensions, in raw form. When parsing
	// CSRs, this can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any CSR
	// marshaled by CreateCertificateRequest. Values override any extensions
	// that would otherwise be produced based on the other fields but are
	// overridden by any extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated by ParseCertificateRequest,
	// see Extensions instead.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS #9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// parseRawAttributes Unmarshals RawAttributes into AttributeTypeAndValueSETs.
func parseRawAttributes(rawAttributes []asn1.RawValue) []pkix.AttributeTypeAndValueSET {
	var attributes []pkix.AttributeTypeAndValueSET
	for _, rawAttr := range rawAttributes {
		var attr pkix.AttributeTypeAndValueSET
		rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		// Ignore attributes that don't parse into pkix.AttributeTypeAndValueSET
		// (i.e.: challengePassword or unstructuredName).
		if err == nil && len(rest) == 0 {
			attributes = append(attributes, attr)
		}
	}
	return attributes
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, error) {
	// pkcs10Attribute reflects the Attribute structure from RFC 2986, Section 4.1.
	type pkcs10Attribute struct {
		Id     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.Id.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//   - DNSNames
//   - EmailAddresses
//   - IPAddresses
//   - URIs
//   - ExtraExtensions
//   - Attributes (deprecated)
//
// priv is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR. It must implement crypto.Signer and its
// Public() method must return a *rsa.PublicKey or a *ecdsa.PublicKey or a
// ed25519.PublicKey. (A *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey satisfies this.)
//
// The returned slice is the certificate request in DER encoding.
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	var hashFunc Hash
	var sigAlgo pkix.AlgorithmIdentifier
	hashFunc, sigAlgo, err = signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	extensions, err := buildCSRExtensions(template)
	if err != nil {
		return nil, err
	}

	// Make a copy of template.Attributes because we may alter it below.
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}

	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}

			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)

			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}

				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}

			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	signed := tbsCSRContents
	switch template.SignatureAlgorithm {
	case SM2WithSM3, SM2WithSHA1, SM2WithSHA256, PureSm2Hybrid, UnknownSignatureAlgorithm, PureDilithium2:
		break
	default:
		h := hashFunc.New()
		h.Write(tbsCSRContents)
		signed = h.Sum(nil)
	}

	var signature []byte
	signature, err = key.Sign(rand, signed, hashFunc)
	if err != nil {
		return
	}
	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, error) {
	out := &CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromAI(in.SignatureAlgorithm),

		PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version:    in.TBSCSR.Version,
		Attributes: parseRawAttributes(in.TBSCSR.RawAttributes),
	}

	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}
	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		switch {
		case extension.Id.Equal(oidExtensionSubjectAltName):
			out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() error {
	return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificateRequest, c.Signature, c.PublicKey)
}

// RevocationList contains the fields used to create an X.509 v2 Certificate
// Revocation list with CreateRevocationList.
type RevocationList struct {
	// SignatureAlgorithm is used to determine the signature algorithm to be
	// used when signing the CRL. If 0 the default algorithm for the signing
	// key will be used.
	SignatureAlgorithm SignatureAlgorithm

	// RevokedCertificates is used to populate the revokedCertificates
	// sequence in the CRL, it may be empty. RevokedCertificates may be nil,
	// in which case an empty CRL will be created.
	RevokedCertificates []pkix.RevokedCertificate

	// Number is used to populate the X.509 v2 cRLNumber extension in the CRL,
	// which should be a monotonically increasing sequence number for a given
	// CRL scope and CRL issuer.
	Number *big.Int
	// ThisUpdate is used to populate the thisUpdate field in the CRL, which
	// indicates the issuance date of the CRL.
	ThisUpdate time.Time
	// NextUpdate is used to populate the nextUpdate field in the CRL, which
	// indicates the date by which the next CRL will be issued. NextUpdate
	// must be greater than ThisUpdate.
	NextUpdate time.Time
	// ExtraExtensions contains any additional extensions to add directly to
	// the CRL.
	ExtraExtensions []pkix.Extension
}

// CreateRevocationList creates a new X.509 v2 Certificate Revocation List,
// according to RFC 5280, based on template.
//
// The CRL is signed by priv which should be the private key associated with
// the public key in the issuer certificate.
//
// The issuer may not be nil, and the crlSign bit must be set in KeyUsage in
// order to use it as a CRL issuer.
//
// The issuer distinguished name CRL field and authority key identifier
// extension are populated using the issuer certificate. issuer must have
// SubjectKeyId set.
func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *Certificate, priv crypto.Signer) ([]byte, error) {
	if template == nil {
		return nil, errors.New("x509: template can not be nil")
	}
	if issuer == nil {
		return nil, errors.New("x509: issuer can not be nil")
	}
	if (issuer.KeyUsage & KeyUsageCRLSign) == 0 {
		return nil, errors.New("x509: issuer must have the crlSign key usage bit set")
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, errors.New("x509: issuer certificate doesn't contain a subject key identifier")
	}
	if template.NextUpdate.Before(template.ThisUpdate) {
		return nil, errors.New("x509: template.ThisUpdate is after template.NextUpdate")
	}
	if template.Number == nil {
		return nil, errors.New("x509: template contains nil Number field")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(template.RevokedCertificates))
	for i, rc := range template.RevokedCertificates {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	aki, err := asn1.Marshal(authKeyId{Id: issuer.SubjectKeyId})
	if err != nil {
		return nil, err
	}
	crlNum, err := asn1.Marshal(template.Number)
	if err != nil {
		return nil, err
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:    1, // v2
		Signature:  signatureAlgorithm,
		Issuer:     issuer.Subject.ToRDNSequence(),
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
		Extensions: []pkix.Extension{
			{
				Id:    oidExtensionAuthorityKeyId,
				Value: aki,
			},
			{
				Id:    oidExtensionCRLNumber,
				Value: crlNum,
			},
		},
	}
	if len(revokedCertsUTC) > 0 {
		tbsCertList.RevokedCertificates = revokedCertsUTC
	}

	if len(template.ExtraExtensions) > 0 {
		tbsCertList.Extensions = append(tbsCertList.Extensions, template.ExtraExtensions...)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	input := tbsCertListContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(tbsCertListContents)
		input = h.Sum(nil)
	}
	var signerOpts crypto.SignerOpts = hashFunc
	if template.SignatureAlgorithm.isRSAPSS() {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.Hash(hashFunc),
		}
	}

	signature, err := priv.Sign(rand, input, signerOpts)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
