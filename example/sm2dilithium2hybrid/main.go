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
			CommonName: "lalala",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
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

	// 待签署证书及其私钥公钥==================================
	sigeCert("lalala", ca, caSelfSignedPrivateKey, caSelfSigned)
	sigeCert("lalala2", ca, caSelfSignedPrivateKey, caSelfSigned)
}

func sigeCert(cn string, ca *x509.Certificate, caSelfSignedPrivateKey *sm2dilithium2hybrid.PrivateKey, caSelfSigned []byte) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Country: []string{cn},
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
	log.Println("write to", certFile)
	os.WriteFile(certFile, certSigned, 0777) // cert 写入文件

	certPrivateKeyFile := cn + ".key"
	certPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(certPrivateKey) // 将私钥转换为 DER 编码格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return err
	}
	log.Println("write to", certPrivateKeyFile)
	os.WriteFile(certPrivateKeyFile, certPrivateKeyDER, 0777) // 私钥写入文件
	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: certPrivateKeyDER})
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: certSigned})
	ca_tr, err := x509.ParseCertificate(caSelfSigned)

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
