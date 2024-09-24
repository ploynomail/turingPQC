package dilithium2

import (
	"testing"
)

func TestDilithium2(t *testing.T) {
	priKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello,world")
	sig, err := priKey.SignPQC(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !priKey.Verify(msg, sig) {
		t.Fatal("verify failed")
	}
	t.Log("verify success")

	msg2 := []byte("hello,world@@@")
	sig2, err := priKey.SignPQC(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if !priKey.Verify(msg2, sig2) {
		t.Fatal("verify failed")
	}
	t.Log("verify success")
}
