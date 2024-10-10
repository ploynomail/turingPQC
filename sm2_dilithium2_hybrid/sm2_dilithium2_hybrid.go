package sm2dilithium2hybrid

import (
	"crypto"
	"fmt"
	"io"

	"github.com/ploynomail/turingPQC/pqc/dilithium/dilithium2"
	"github.com/ploynomail/turingPQC/sm2"
)

type PublicKey struct {
	SM2PublicKey        sm2.PublicKey
	Dilithium2PublicKey dilithium2.PublicKey
}

func (pub *PublicKey) Equal(crypto.PublicKey) bool {
	return true
}

type PrivateKey struct {
	PublicKey
	SM2PrivateKey        sm2.PrivateKey
	Dilithium2PrivateKey dilithium2.PrivateKey
}

// The hybrid private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error) {
	var signature []byte
	var err error
	dilithium2Sig, err := priv.Dilithium2PrivateKey.SignPQC(msg)
	if err != nil {
		return nil, err
	}
	sm2Sig, err := priv.SM2PrivateKey.Sign(random, msg, signer)
	if err != nil {
		return nil, err
	}
	signature = append(sm2Sig, dilithium2Sig...)
	return signature, nil
}

func (pub *PublicKey) Verify(msg []byte, sig []byte) bool {
	sm2Sig := sig[:len(sig)-2420]
	if !pub.SM2PublicKey.Verify(msg, sm2Sig) {
		fmt.Println("sm2 verify failed")
		return false
	}
	dilithium2Sig := sig[len(sig)-2420:]
	return pub.Dilithium2PublicKey.Verify(msg, dilithium2Sig)
}

func Verify(pub *PublicKey, msg []byte, sig []byte) bool {
	return pub.Verify(msg, sig)
}
