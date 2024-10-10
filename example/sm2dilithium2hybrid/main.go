package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	sm2dilithium2hybrid "github.com/ploynomail/turingPQC/sm2_dilithium2_hybrid"
	"github.com/ploynomail/turingPQC/x509"
)

func main() {
	// ca 证书
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{""},
			OrganizationalUnit: []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	// 私钥及公钥 格式
	caSelfSignedPrivateKey, _ := sm2dilithium2hybrid.GenerateKey(rand.Reader)
	caSelfSignedPublicKey := &caSelfSignedPrivateKey.PublicKey

	// 自签证书 []byte
	caSelfSigned, err := x509.CreateCertificate(rand.Reader, ca, ca, caSelfSignedPublicKey, caSelfSignedPrivateKey)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	caSelfSignedFile := "ca.pem"
	log.Println("write to", caSelfSignedFile)
	os.WriteFile(caSelfSignedFile, caSelfSigned, 0777) // 将自签证书写入文件
	caSelfSignedPrivateKeyFile := "ca.key"

	caSelfSignedPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(caSelfSignedPrivateKey) // 将私钥转换为 DER 格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: caSelfSignedPrivateKeyDER})
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: caSelfSigned})
	log.Println("write to", caSelfSignedPrivateKeyFile)
	os.WriteFile(caSelfSignedPrivateKeyFile, caSelfSignedPrivateKeyDER, 0777) // 将 DER 编码私钥写入文件
}
