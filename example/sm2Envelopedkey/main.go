package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/ploynomail/turingPQC/sm2"
	"github.com/ploynomail/turingPQC/x509"
)

func generateSigeKeyPair() (*sm2.PrivateKey, *sm2.PublicKey) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key pair: %v", err)
	}

	PrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey) // 将私钥转换为 DER 格式
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}
	PrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: PrivateKeyDER})
	os.WriteFile("./sige_key.pem", PrivateKeyPem, 0777)               // 将 DER 编码私钥写入文件
	PubKeyDER, err := x509.MarshalSm2PublicKey(&privateKey.PublicKey) // 将公钥转换为 DER 格式
	if err != nil {
		log.Fatalf("failed to marshal public key: %v", err)
	}
	PubKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: PubKeyDER})
	os.WriteFile("./sige_pub.pem", PubKeyPem, 0777) // 将 DER 编码公钥写入文件
	return privateKey, &privateKey.PublicKey
}

func generateEncKeyPair() (*sm2.PrivateKey, *sm2.PublicKey) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key pair: %v", err)
	}

	PrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey) // 将私钥转换为 DER 格式
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}
	PrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: PrivateKeyDER})
	os.WriteFile("./enc_key.pem", PrivateKeyPem, 0777)                // 将 DER 编码私钥写入文件
	PubKeyDER, err := x509.MarshalSm2PublicKey(&privateKey.PublicKey) // 将公钥转换为 DER 格式
	if err != nil {
		log.Fatalf("failed to marshal public key: %v", err)
	}
	PubKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: PubKeyDER})
	os.WriteFile("./enc_pub.pem", PubKeyPem, 0777) // 将 DER 编码公钥写入文件
	return privateKey, &privateKey.PublicKey
}

func main() {
	sigeKey, sigePub := generateSigeKeyPair()
	sigeKeyDER, err := x509.MarshalPKCS8PrivateKey(sigeKey)
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}
	sigeKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sigeKeyDER})
	log.Printf("sigeKey: %s", sigeKeyPem)
	encKey, _ := generateEncKeyPair()
	encKeyDER, err := x509.MarshalPKCS8PrivateKey(encKey)
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}
	encKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encKeyDER})
	log.Printf("encKey: %s", encKeyPem)
	// ASN.1 格式数字信封
	// 生成数字信封
	envelopedData, err := x509.GenerateSM2EnvelopedKey(encKey, sigePub, sm2.C1C3C2)
	if err != nil {
		log.Fatalf("failed to generate enveloped key: %v", err)
	}

	// 将数字信封序列化为 hex 格式
	hexData := hex.EncodeToString(envelopedData)
	fmt.Println(hexData)
	// 解析数字信封
	decodedData, err := hex.DecodeString(hexData)
	if err != nil {
		log.Fatalf("failed to decode hex data: %v", err)
	}
	pk, err := x509.ParseSM2EnvelopedKey(decodedData, sigeKey, sm2.C1C3C2)
	if err != nil {
		log.Fatalf("failed to parse enveloped key: %v", err)
	}
	pkDER, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}
	pkPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkDER})
	log.Printf("pk: %s", pkPem)
}
