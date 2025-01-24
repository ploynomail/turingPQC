package x509

import (
	"bytes"
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
