package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/utils/logger"
)

// Important to not get nullpointer on logger!
func init() {
	logger.StOutInit()
}

func TestCreateJwks(t *testing.T) {
	key, _ := rsaa.ParseRsaKeys("../test-resources/private.pem", "", "../test-resources/public.pem")
	j := jwksHandler{key}

	keys, err := j.createJwks()
	if err != nil {
		t.Errorf("EUnexpected error: %v", err)
	}

	var res = string(len(keys.Keys))
	var exp = string(1)
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	k := keys.Keys[0]
	res = k.Alg
	exp = "RSA256"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.Kty
	exp = "RSA"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.Use
	exp = "sig"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.X5c[0]
	exp = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAss+dtqxnhnROqkhnrDvqpP8pLLcaf0elK+JMajJ04a7T+dyd2fdq5PJbfqh0O39IbrIZblYkf2kLqp61qEqHpPs2NfIGKYG27YOInbBqddeGhaCxPf727G77Bwu0FQYgWc1j9Yv8kw65e9Zpfc8KzKU3pwQwwMnkCxc9r84d3Z9uNyOI2c/VVeRUqMreqDvLoIYKDc4rn3Q8z3gGMuyWzImzt/9MF6Kitp8ueYWPpGCxJVjaO7DabZHTujIFwC+YjS6vQzhs9pucwgcUvhOEQwRqR4NEG+jnAajtKKmKyDn0/o9V5r3Mo/qLrXNblw3G/EhW5y1Su4OdY8r90bdrqwIDAQAB"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.N
	exp = "ss+dtqxnhnROqkhnrDvqpP8pLLcaf0elK+JMajJ04a7T+dyd2fdq5PJbfqh0O39IbrIZblYkf2kLqp61qEqHpPs2NfIGKYG27YOInbBqddeGhaCxPf727G77Bwu0FQYgWc1j9Yv8kw65e9Zpfc8KzKU3pwQwwMnkCxc9r84d3Z9uNyOI2c/VVeRUqMreqDvLoIYKDc4rn3Q8z3gGMuyWzImzt/9MF6Kitp8ueYWPpGCxJVjaO7DabZHTujIFwC+YjS6vQzhs9pucwgcUvhOEQwRqR4NEG+jnAajtKKmKyDn0/o9V5r3Mo/qLrXNblw3G/EhW5y1Su4OdY8r90bdrqw"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.E
	exp = "AQAB"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.Kid
	exp = "iu/doGX/WCNvVzSzGspKSJ0/ekM"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
	res = k.X5t
	exp = "iu/doGX/WCNvVzSzGspKSJ0/ekM"
	if res != exp {
		t.Errorf("Expected: %v, but got: %v", exp, res)
	}
}

func TestCreateJwksNEToPrivateKey(t *testing.T) {
	key, _ := rsaa.ParseRsaKeys("../test-resources/private.pem", "", "../test-resources/public.pem")
	j := jwksHandler{key}

	keys, err := j.createJwks()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	k := keys.Keys[0]

	// decode the base64 bytes for n
	nb, err := base64.RawStdEncoding.DecodeString(k.N)
	if err != nil {
		t.Errorf("Dekode N failure: %v", err)
	}
	var e int
	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if k.E == "AQAB" || k.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		t.Errorf("Dekode E failure: %v", err)
	}

	// Make public key and validate
	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}
	if pk.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("Decode N not equal to key.N")
	}
	if pk.E != key.PublicKey.E {
		t.Error("Decode E not equal to key.E")
	}

	// Marshal key
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Error("Marshall PKIX PublicKey failure")
	}

	//
	exp := base64.RawStdEncoding.EncodeToString(der)
	res := k.X5c[0]
	if exp != res {
		t.Errorf("PublicKey: %v not as expected: %v", res, exp)
	}
	/*
		// Print PEM cert
		block := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		}
		var out bytes.Buffer
		pem.Encode(&out, block)
		fmt.Println(out.String())
	*/
}
