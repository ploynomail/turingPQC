package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ploynomail/turingPQC/pqc/dilithium/dilithium2"
	"github.com/ploynomail/turingPQC/x509"
)

func main() {
	// 生成 自签CA 证书
	GenerateSelfSignerCACert()
	CreateCSR("test")
	ParseCSR("test")
	SigeCertFormCSR("test")
}

func GenerateSelfSignerCACert() {
	// ca 证书
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:            []string{"China"},
			Province:           []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
			Organization:       []string{"TuringQ"},
			OrganizationalUnit: []string{"DevOps"},
			CommonName:         "TuringQ DevOps CA",
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
	caSelfSignedPrivateKey, _ := dilithium2.GenerateKey()
	caSelfSignedPublicKey := &caSelfSignedPrivateKey.PublicKey
	// 自签证书 []byte
	caSelfSigned, err := x509.CreateCertificate(rand.Reader, ca, ca, caSelfSignedPublicKey, caSelfSignedPrivateKey)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	caSelfSignedFile := "ca.pem"
	log.Println("write to", caSelfSignedFile)
	caSelfSignedPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caSelfSigned})
	os.WriteFile(caSelfSignedFile, caSelfSignedPem, 0777) // 将自签证书写入文件

	caSelfSignedPrivateKeyFile := "ca.key"

	caSelfSignedPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(caSelfSignedPrivateKey) // 将私钥转换为 DER 格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return
	}
	log.Println("write to", caSelfSignedPrivateKeyFile)
	caSelfSignedPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caSelfSignedPrivateKeyDER})
	os.WriteFile(caSelfSignedPrivateKeyFile, caSelfSignedPrivateKeyPem, 0777) // 将 DER 编码私钥写入文件
}

func CreateCSR(id string) {
	// 生成私钥
	privateKeyPath := fmt.Sprintf("%s.key", id)
	privateKey, _ := dilithium2.GenerateKey()
	privateKeyDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	os.WriteFile(privateKeyPath, p, 0777)
	// 创建CSR模板
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: id,
		},
		SignatureAlgorithm: x509.PureDilithium2,
	}
	// 创建CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		panic(err)
	}

	// 将CSR序列化为PEM格式
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	csrPath := fmt.Sprintf("%s.csr", id)
	// 将CSR写入文件
	err = os.WriteFile(csrPath, csrPEM, 0644)
	if err != nil {
		panic(err)
	}
}

func ParseCSR(id string) {
	csrPath := fmt.Sprintf("%s.csr", id)
	// 从文件中读取CSR
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		panic(err)
	}

	// 解码PEM格式的CSR
	block, _ := pem.Decode(csrPEM)

	// 解析CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 输出CSR信息
	fmt.Printf("Subject: %v\n", csr.Subject)
	fmt.Printf("Signature Algorithm: %v\n", csr.SignatureAlgorithm)
}

func SigeCertFormCSR(id string) {
	// 读取CA证书
	caCertPEM, err := os.ReadFile("ca.pem")
	if err != nil {
		panic(err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// 读取CA私钥
	caKeyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		panic(err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	// caKey, err := x509.ParsePKCS8UnecryptedPrivateKey(caKeyBlock.Bytes)

	if err != nil {
		panic(err)
	}
	// 读取CSR
	csrPath := fmt.Sprintf("%s.csr", id)
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		panic(err)
	}
	csrBlock, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		panic(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	// 生成证书
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, csr.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	// 将证书序列化为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// 将证书写入文件
	pemPath := fmt.Sprintf("%s.pem", id)
	err = os.WriteFile(pemPath, certPEM, 0644)
	if err != nil {
		panic(err)
	}
}
