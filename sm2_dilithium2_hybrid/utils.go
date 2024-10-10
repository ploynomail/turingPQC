package sm2dilithium2hybrid

import (
	"io"

	"github.com/ploynomail/turingPQC/pqc/dilithium/dilithium2"
	"github.com/ploynomail/turingPQC/sm2"
)

func GenerateKey(random io.Reader) (*PrivateKey, error) {
	sm2Key, err := sm2.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	dilithium2Key, err := dilithium2.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			SM2PublicKey:        sm2Key.PublicKey,
			Dilithium2PublicKey: dilithium2Key.PublicKey,
		},
		SM2PrivateKey:        *sm2Key,
		Dilithium2PrivateKey: *dilithium2Key,
	}, nil
}
