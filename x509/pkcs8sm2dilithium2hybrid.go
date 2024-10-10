package x509

import sm2dilithium2hybrid "github.com/ploynomail/turingPQC/sm2_dilithium2_hybrid"

func MarshalPKCS8SM2Dilithium2HybridPrivateKey(key sm2dilithium2hybrid.PrivateKey) ([]byte, error) {
	return MarshalPKCS8PrivateKey(key)
}
