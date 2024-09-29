package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ploynomail/turingPQC/sm2"
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
	caSelfSignedPrivateKey, _ := sm2.GenerateKey(rand.Reader)
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

	caSelfSignedPrivateKeyDER, err := x509.MarshalSm2PrivateKey(caSelfSignedPrivateKey, nil) // 将私钥转换为 DER 格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: caSelfSignedPrivateKeyDER})
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: caSelfSigned})
	log.Println("write to", caSelfSignedPrivateKeyFile)
	os.WriteFile(caSelfSignedPrivateKeyFile, caSelfSignedPrivateKeyDER, 0777) // 将 DER 编码私钥写入文件

	// 待签署证书及其私钥公钥
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{""},
			OrganizationalUnit: []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	certPrivateKey, _ := sm2.GenerateKey(rand.Reader)
	certPublicKey := &certPrivateKey.PublicKey

	// 使用自签CA 对 证书签署
	certSigned, err2 := x509.CreateCertificate(rand.Reader, cert, ca, certPublicKey, caSelfSignedPrivateKey)
	if err2 != nil {
		log.Println("create cert2 failed", err2)
		return
	}

	certFile := "cert.pem"
	log.Println("write to", certFile)
	os.WriteFile(certFile, certSigned, 0777) // cert 写入文件

	certPrivateKeyFile := "cert.key"
	certPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(certPrivateKey) // 将私钥转换为 DER 编码格式
	if err != nil {
		log.Println("marshal pkcs8 failed", err)
		return
	}
	log.Println("write to", certPrivateKeyFile)
	os.WriteFile(certPrivateKeyFile, certPrivateKeyDER, 0777) // 私钥写入文件
	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: certPrivateKeyDER})
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: certSigned})
	ca_tr, err := x509.ParseCertificate(caSelfSigned)

	if err != nil {
		log.Println("parse ca failed", err)
		return
	}

	cert_tr, err := x509.ParseCertificate(certSigned)

	if err != nil {
		log.Println("parse cert failed", err)
		return
	}

	err = cert_tr.CheckSignatureFrom(ca_tr)
	log.Println("check signature", err)
}
