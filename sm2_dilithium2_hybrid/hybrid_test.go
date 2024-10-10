package sm2dilithium2hybrid

import (
	"crypto/rand"
	"testing"
)

func TestHybrid(t *testing.T) {
	keyPair, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	msg := []byte("hello wsssorld")
	signature, err := keyPair.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Error(err)
		return
	}
	if !keyPair.PublicKey.Verify(msg, signature) {
		t.Error("verify failed")
		return
	}

	t.Log("success")
}
