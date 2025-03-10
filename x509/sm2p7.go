package x509

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/ploynomail/turingPQC/sm2"
	"github.com/ploynomail/turingPQC/sm4"
)

var oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}

type sm2Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

// 定义数字信封结构
type SM2EnvelopedKey struct {
	SymAlgID               pkix.AlgorithmIdentifier `asn1:""`
	SymEncryptedKey        sm2Cipher                `asn1:""`
	SM2PublicKey           asn1.BitString           `asn1:""`
	SM2EncryptedPrivateKey asn1.BitString           `asn1:""`
}

// 生成对称密钥
func generateSymmetricKey() ([]byte, error) {
	key := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// 使用对称密钥加密数据（ECB模式）
func encryptWithSymmetricKey(key []byte, plaintext []byte) ([]byte, error) {
	ecbMsg, err := sm4.Sm4EcbWithNone(key, plaintext, true)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with symmetric key: %v", err)
	}
	return ecbMsg, nil
}

// 使用对称密钥解密数据（ECB模式）
func decryptWithSymmetricKey(key []byte, ciphertext []byte) ([]byte, error) {
	ecbDec, err := sm4.Sm4EcbWithNone(key, ciphertext, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with symmetric key: %v", err)
	}
	return ecbDec, nil
}

// 使用SM2公钥加密对称密钥
func encryptWithSM2PublicKey(publicKey *sm2.PublicKey, plaintext []byte, mode int) ([]byte, error) {
	ciphertext, err := sm2.Encrypt(publicKey, plaintext, rand.Reader, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with SM2 public key: %v", err)
	}
	return ciphertext, nil
}

// 使用SM2私钥解密对称密钥
func decryptWithSM2PrivateKey(privateKey *sm2.PrivateKey, ciphertext []byte, mode int) ([]byte, error) {
	plaintext, err := sm2.Decrypt(privateKey, ciphertext, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with SM2 private key: %v", err)
	}
	return plaintext, nil
}

// 生成数字信封
func GenerateSM2EnvelopedKey(sm2PrivateKey *sm2.PrivateKey, sm2PublicKey *sm2.PublicKey, mode int) ([]byte, error) {
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
	encryptedPrivateKey = encryptedPrivateKey[:len(sm2PrivateKey.D.Bytes())]
	// 3. 使用SM2公钥加密对称密钥
	encryptedSymmetricKey, err := encryptWithSM2PublicKey(sm2PublicKey, symmetricKey, mode)
	if err != nil {
		return nil, err
	}

	encryptedSymmetricKey = encryptedSymmetricKey[1:]
	x := new(big.Int).SetBytes(encryptedSymmetricKey[:32])
	y := new(big.Int).SetBytes(encryptedSymmetricKey[32:64])
	hash := encryptedSymmetricKey[64:96]
	cipherText := encryptedSymmetricKey[96:]
	Cipher := sm2Cipher{
		XCoordinate: x,
		YCoordinate: y,
		HASH:        hash,
		CipherText:  cipherText,
	}

	// 4. 序列化私钥的SM2公钥
	sm2PublicKeyBytes := asn1.BitString{Bytes: elliptic.Marshal(sm2.P256Sm2(), sm2PrivateKey.PublicKey.X, sm2PrivateKey.PublicKey.Y)}

	// 5. 封装到数字信封中
	envelopedKey := SM2EnvelopedKey{
		SymAlgID:               pkix.AlgorithmIdentifier{Algorithm: oidSM4ECB, Parameters: asn1.NullRawValue},
		SymEncryptedKey:        Cipher,
		SM2PublicKey:           sm2PublicKeyBytes,
		SM2EncryptedPrivateKey: asn1.BitString{Bytes: encryptedPrivateKey},
	}
	return asn1.Marshal(envelopedKey)
}

// 解析数字信封
func ParseSM2EnvelopedKey(envelopedKeyData []byte, sm2PrivateKey *sm2.PrivateKey, mode int) (*sm2.PrivateKey, error) {
	var sm2EnvelopedKey SM2EnvelopedKey
	_, err := asn1.Unmarshal(envelopedKeyData, &sm2EnvelopedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SM2 enveloped key: %v", err)
	}

	x := sm2EnvelopedKey.SymEncryptedKey.XCoordinate.Bytes()
	y := sm2EnvelopedKey.SymEncryptedKey.YCoordinate.Bytes()
	hash := sm2EnvelopedKey.SymEncryptedKey.HASH
	cipherText := sm2EnvelopedKey.SymEncryptedKey.CipherText
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)          // x分量
	c = append(c, y...)          // y分
	c = append(c, hash...)       // x分量
	c = append(c, cipherText...) // y分
	c = append([]byte{0x04}, c...)
	encryptedSymmetricKey := c
	// 1. 使用SM2私钥解密对称密钥
	symmetricKey, err := decryptWithSM2PrivateKey(sm2PrivateKey, encryptedSymmetricKey, sm2.C1C3C2)
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
