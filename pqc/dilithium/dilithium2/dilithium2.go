package dilithium2

import (
	"bytes"
	"crypto"
	"io"
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	sigName        = "Dilithium2"
	PublicKeySize  = 1312
	PrivateKeySize = 2528
)

// 公钥
type PublicKey struct {
	Pk []byte
}

// 私钥
type PrivateKey struct {
	PublicKey
	Sk []byte
}

func GenerateKey() (*PrivateKey, error) {
	var signer = oqs.Signature{}
	defer signer.Clean() // clean up even in case of panic

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}
	pk, err := signer.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	sk := signer.ExportSecretKey()
	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			Pk: bytes.Clone(pk),
		},
		Sk: bytes.Clone(sk),
	}

	return privateKey, err
}

func (priv *PrivateKey) SignPQC(msg []byte) (sig []byte, err error) {
	var signer = oqs.Signature{}
	defer signer.Clean()
	privKey := bytes.Clone(priv.Sk)
	if err := signer.Init(sigName, privKey); err != nil {
		return nil, err
	}

	sign, err := signer.Sign(msg)
	if err != nil {
		return nil, err
	}
	sig = append([]byte{}, sign...)
	return sig, err
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignPQC(digest)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// func (pub *PublicKey) Verify(msg []byte, sig []byte) bool
func (pub *PublicKey) Verify(msg []byte, signature []byte) bool {
	return Verify(pub, msg, signature)
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	return true
}

func Verify(pubkey *PublicKey, msg, signature []byte) bool {
	var verifier = oqs.Signature{}
	defer verifier.Clean()

	if err := verifier.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}
	isValid, err := verifier.Verify(msg, signature, pubkey.Pk)
	if err != nil {
		log.Fatal(err)
	}
	return isValid
}
