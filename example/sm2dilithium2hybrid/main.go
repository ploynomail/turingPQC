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

	sm2dilithium2hybrid "github.com/ploynomail/turingPQC/sm2_dilithium2_hybrid"
	"github.com/ploynomail/turingPQC/x509"
)

func main() {
	// ca 证书
	// SelfSignCa()
	// 待签署证书及其私钥公钥==================================
	// caSelfSignedPrivateKey, err := ReadAndParsePrivateKey("ca.key")
	// if err != nil {
	// 	log.Println("read ca private key failed", err)
	// 	return
	// }
	// caCert, err := ReadAndParseCert("ca.pem")
	// if err != nil {
	// 	log.Println("read ca cert failed", err)
	// 	return
	// }
	// SigeCert("7549d76e-82b7-4bc0-a990-a5bc1a0af36b", caCert, caSelfSignedPrivateKey)
	// SigeCert("e963dbc5-7319-44d1-a071-8e6eef321747", caCert, caSelfSignedPrivateKey)
	CreateCSR("7549d76e-82b7-4bc0-a990-a5bc1a0af36b")
	ParseCSR("7549d76e-82b7-4bc0-a990-a5bc1a0af36b")
	SigeCertFormCSR("7549d76e-82b7-4bc0-a990-a5bc1a0af36b")
	CreateCSR("e963dbc5-7319-44d1-a071-8e6eef321747")
	ParseCSR("e963dbc5-7319-44d1-a071-8e6eef321747")
	SigeCertFormCSR("e963dbc5-7319-44d1-a071-8e6eef321747")
}

func SelfSignCa() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1650),
		Subject: pkix.Name{
			CommonName: "ROOT CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10年
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment,
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
	caSelfSignedPrivateKeyFile := "ca.key"
	caSelfSignedPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(caSelfSignedPrivateKey) // 将私钥转换为 DER 格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return
	}
	log.Println("write to", caSelfSignedPrivateKeyFile)
	Der2PemPrivateKey(caSelfSignedPrivateKeyDER, caSelfSignedPrivateKeyFile) // 私钥写入文件
	Der2PemCert(caSelfSigned, caSelfSignedFile)                              // 证书写入文件
}

func SigeCert(cn string, ca *x509.Certificate, caSelfSignedPrivateKey *sm2dilithium2hybrid.PrivateKey) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	certPrivateKey, _ := sm2dilithium2hybrid.GenerateKey(rand.Reader)
	certPublicKey := &certPrivateKey.PublicKey

	// 使用自签CA 对 证书签署
	certSigned, err2 := x509.CreateCertificate(rand.Reader, cert, ca, certPublicKey, caSelfSignedPrivateKey)
	if err2 != nil {
		log.Println("create cert2 failed", err2)
		return err2
	}
	certFile := cn + ".pem"

	certPrivateKeyFile := cn + ".key"
	certPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(certPrivateKey) // 将私钥转换为 DER 编码格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return err
	}
	Der2PemPrivateKey(certPrivateKeyDER, certPrivateKeyFile) // 私钥写入文件
	Der2PemCert(certSigned, certFile)                        // 证书写入文件

	// 验证签名
	caCert, err := ReadCert2Der("ca.pem")
	if err != nil {
		log.Println("read ca cert failed", err)
	}
	ca_tr, err := x509.ParseCertificate(caCert)

	if err != nil {
		log.Println("parse ca failed", err)
		return err
	}

	cert_tr, err := x509.ParseCertificate(certSigned)

	if err != nil {
		log.Println("parse cert failed", err)
		return err
	}

	err = cert_tr.CheckSignatureFrom(ca_tr)
	log.Println("check signature", err)
	return nil
}

func Der2PemCert(der []byte, pemFileName string) {
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	os.WriteFile(pemFileName, p, 0777)
}

func Der2PemPrivateKey(der []byte, pemFileName string) {
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	os.WriteFile(pemFileName, p, 0777)
}

func ReadAndParseCert(pemFileName string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(pemFileName)
	if err != nil {
		log.Println("read cert failed", err)
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("parse cert failed", err)
		return nil, err
	}
	log.Println("parse cert success")
	return cert, nil
}

func ReadAndParsePrivateKey(pemFileName string) (*sm2dilithium2hybrid.PrivateKey, error) {
	pemData, err := os.ReadFile(pemFileName)
	if err != nil {
		log.Println("read private key failed", err)
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Println("parse private key failed", err)
		return nil, err
	}
	log.Println("parse private key success")
	return privateKey.(*sm2dilithium2hybrid.PrivateKey), nil
}

func ReadCert(pemFileName string) ([]byte, error) {
	pemData, err := os.ReadFile(pemFileName)
	if err != nil {

		return nil, err
	}
	return pemData, nil
}

func ReadCert2Der(pemFileName string) ([]byte, error) {
	pemData, err := os.ReadFile(pemFileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	return block.Bytes, nil
}

func GenPrivateKey() {
	privateKey, _ := sm2dilithium2hybrid.GenerateKey(rand.Reader)
	privateKeyDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	Der2PemPrivateKey(privateKeyDER, "mycompany-private.key")
}

func CreateCSR(id string) {
	// 生成私钥
	privateKeyPath := fmt.Sprintf("%s.key", id)
	privateKey, _ := sm2dilithium2hybrid.GenerateKey(rand.Reader)
	privateKeyDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	os.WriteFile(privateKeyPath, p, 0777)
	// 创建CSR模板
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: id,
		},
		SignatureAlgorithm: x509.PureSm2Hybrid,
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
