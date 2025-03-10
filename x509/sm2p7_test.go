package x509

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ploynomail/turingPQC/sm4"
)

func TestEncryptWithSymmetricKey(t *testing.T) {
	key := []byte("1234567890abcdef") // 16 bytes key for SM4
	plaintext := []byte("This is a test message.")

	// Encrypt the plaintext
	ciphertext, err := encryptWithSymmetricKey(key, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt with symmetric key: %v", err)
	}
	// Decrypt the ciphertext to verify
	decryptedText, err := sm4.Sm4Ecb(key, ciphertext, false)
	if err != nil {
		t.Fatalf("Failed to decrypt with symmetric key: %v", err)
	}

	// Check if the decrypted text matches the original plaintext
	if !bytes.Equal(decryptedText, plaintext) {
		t.Errorf("Decrypted text does not match the original plaintext. Got: %s, Want: %s", decryptedText, plaintext)
	}
}

func TestDecryptWithSymmetricKey(t *testing.T) {
	key := []byte("1234567890abcdef") // 16 bytes key for SM4
	plaintext := []byte("This is a test message.")

	// Encrypt the plaintext
	ciphertext, err := sm4.Sm4Ecb(key, plaintext, true)
	if err != nil {
		t.Fatalf("Failed to encrypt with symmetric key: %v", err)
	}

	// Decrypt the ciphertext
	decryptedText, err := decryptWithSymmetricKey(key, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt with symmetric key: %v", err)
	}

	// Check if the decrypted text matches the original plaintext
	if !bytes.Equal(decryptedText, plaintext) {
		t.Errorf("Decrypted text does not match the original plaintext. Got: %s, Want: %s", decryptedText, plaintext)
	}
}

func TestDecryptWithSymmetricKey2(t *testing.T) {
	key, _ := hex.DecodeString("3ed71da2d1a60f041099592c048eb776")
	plaintext, _ := hex.DecodeString("6fd84590b4293ac7e33068aeae83790305a354a70c3d00e69006d768877fbaf5")

	// Encrypt the plaintext
	ciphertext, err := sm4.Sm4EcbWithNone(key, plaintext, true)
	if err != nil {
		t.Fatalf("Failed to encrypt with symmetric key: %v", err)
	}
	// Decrypt the ciphertext
	decryptedText, err := decryptWithSymmetricKey(key, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt with symmetric key: %v", err)
	}

	// Check if the decrypted text matches the original plaintext
	if !bytes.Equal(decryptedText, plaintext) {
		t.Errorf("Decrypted text does not match the original plaintext. Got: %s, Want: %s", decryptedText, plaintext)
	}
}
