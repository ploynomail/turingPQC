package x509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/ploynomail/turingPQC/sm2"
	"github.com/ploynomail/turingPQC/sm4"
)

var oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}

// 定义数字信封结构
type SM2EnvelopedKey struct {
	SymAlgID               pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	SymEncryptedKey        []byte                   `asn1:"explicit,tag:1"`
	SM2PublicKey           []byte                   `asn1:"explicit,tag:2"`
	SM2EncryptedPrivateKey asn1.BitString           `asn1:"explicit,tag:3"`
}

type SM2EnvelopedKeyBin struct {
	SymAlgID               []byte
	SymEncryptedKey        []byte
	SM2PublicKey           []byte
	SM2EncryptedPrivateKey []byte
}

// 生成对称密钥
func generateSymmetricKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %v", err)
	}
	return key, nil
}

// 使用对称密钥加密数据（ECB模式）
func encryptWithSymmetricKey(key []byte, plaintext []byte) ([]byte, error) {
	ecbMsg, err := sm4.Sm4Ecb(key, plaintext, true)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with symmetric key: %v", err)
	}
	return ecbMsg, nil
}

// 使用对称密钥解密数据（ECB模式）
func decryptWithSymmetricKey(key []byte, ciphertext []byte) ([]byte, error) {
	ecbDec, err := sm4.Sm4Ecb(key, ciphertext, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with symmetric key: %v", err)
	}
	return ecbDec, nil
}

// 使用SM2公钥加密对称密钥
func encryptWithSM2PublicKey(publicKey *sm2.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := sm2.Encrypt(publicKey, plaintext, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with SM2 public key: %v", err)
	}
	return ciphertext, nil
}

// 使用SM2私钥解密对称密钥
func decryptWithSM2PrivateKey(privateKey *sm2.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := sm2.Decrypt(privateKey, ciphertext, sm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with SM2 private key: %v", err)
	}
	return plaintext, nil
}

// 生成数字信封
func GenerateSM2EnvelopedKey(sm2PrivateKey *sm2.PrivateKey, sm2PublicKey *sm2.PublicKey) (*SM2EnvelopedKey, error) {
	// 1. 生成对称密钥
	symmetricKey, err := generateSymmetricKey()
	if err != nil {
		return nil, err
	}

	// 2. 使用对称密钥加密SM2私钥
	sm2PrivateKeyBytes := sm2PrivateKey.D.Bytes()
	encryptedPrivateKey, err := encryptWithSymmetricKey(symmetricKey, sm2PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	// 3. 使用SM2公钥加密对称密钥
	encryptedSymmetricKey, err := encryptWithSM2PublicKey(sm2PublicKey, symmetricKey)
	if err != nil {
		return nil, err
	}

	// 4. 序列化私钥的SM2公钥
	sm2PublicKeyBytes, err := MarshalSm2PublicKey(&sm2PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// 5. 封装到数字信封中
	envelopedKey := &SM2EnvelopedKey{
		SymAlgID:               pkix.AlgorithmIdentifier{Algorithm: oidSM4ECB},
		SymEncryptedKey:        encryptedSymmetricKey,
		SM2PublicKey:           sm2PublicKeyBytes,
		SM2EncryptedPrivateKey: asn1.BitString{Bytes: encryptedPrivateKey},
	}
	return envelopedKey, nil
}

// 解析数字信封
func ParseSM2EnvelopedKey(envelopedKeyData []byte, sm2PrivateKey *sm2.PrivateKey) (*sm2.PrivateKey, error) {
	var sm2EnvelopedKey SM2EnvelopedKey
	_, err := asn1.Unmarshal(envelopedKeyData, &sm2EnvelopedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SM2 enveloped key: %v", err)
	}

	// 1. 使用SM2私钥解密对称密钥
	symmetricKey, err := decryptWithSM2PrivateKey(sm2PrivateKey, sm2EnvelopedKey.SymEncryptedKey)
	if err != nil {
		return nil, err
	}

	// 2. 使用对称密钥解密SM2私钥
	decryptedPrivateKeyBytes, err := decryptWithSymmetricKey(symmetricKey, sm2EnvelopedKey.SM2EncryptedPrivateKey.Bytes)
	if err != nil {
		return nil, err
	}

	// 3. 重建SM2私钥
	decryptedPrivateKey := new(sm2.PrivateKey)
	decryptedPrivateKey.PublicKey.Curve = sm2.P256Sm2()
	decryptedPrivateKey.D = new(big.Int).SetBytes(decryptedPrivateKeyBytes)
	decryptedPrivateKey.PublicKey.X, decryptedPrivateKey.PublicKey.Y = decryptedPrivateKey.PublicKey.Curve.ScalarBaseMult(decryptedPrivateKey.D.Bytes())

	return decryptedPrivateKey, nil
}
