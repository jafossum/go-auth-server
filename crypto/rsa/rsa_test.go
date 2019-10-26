package rsa

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/jafossum/go-auth-server/utils/logger"
)

// Important to not get nullpointer on logger!
func init() {
	logger.StOutInit()
}

func TestParseRsaKeys(t *testing.T) {
	key, _ := ParseRsaKeys("../../test-resources/private.pem", "", "../../test-resources/public.pem")
	// Load known public key
	i := new(big.Int)
	fmt.Sscan("22572797583126508208333445901560037139656373629879674413249261098673426806181161787222066435201157950313840150117803015072794509815691336646548372360320953773496722769276141881378254837258024622737466884584949804068692163546240261665864217005587189026728767894203888073715669863314629439662042798813818818976669376678060551018882158863398341526325317365155218946264289127948115541812414740018118073847979724663513963920241254627172160822071501575972912680172663822393978677629389277978794398852143870088605618452722931996137087138084703869547678886135065613810089101473482631755375759770473026583414050657806165961643", i)
	priv := rsa.PublicKey{
		N: i,
		E: 65537,
	}
	// Make sure key is loaded
	if priv.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("Expected key not loaded")
	}
}

func TestGetSha1Thumbprint(t *testing.T) {
	key, _ := ParseRsaKeys("../../test-resources/private.pem", "", "../../test-resources/public.pem")
	exp := "iu/doGX/WCNvVzSzGspKSJ0/ekM"
	res, err := GetSha1Thumbprint(&key.PublicKey)
	if err != nil {
		t.Errorf("GetSha1Thumbprint(KEY): Unexpected error: %v", err)
	}
	if res != exp {
		t.Errorf("GetSha1Thumbprint(KEY): expected %v, actual %v", exp, res)
	}
}

func TestGetPublicKey(t *testing.T) {
	key, _ := ParseRsaKeys("../../test-resources/private.pem", "", "../../test-resources/public.pem")
	exp := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAss+dtqxnhnROqkhnrDvqpP8pLLcaf0elK+JMajJ04a7T+dyd2fdq5PJbfqh0O39IbrIZblYkf2kLqp61qEqHpPs2NfIGKYG27YOInbBqddeGhaCxPf727G77Bwu0FQYgWc1j9Yv8kw65e9Zpfc8KzKU3pwQwwMnkCxc9r84d3Z9uNyOI2c/VVeRUqMreqDvLoIYKDc4rn3Q8z3gGMuyWzImzt/9MF6Kitp8ueYWPpGCxJVjaO7DabZHTujIFwC+YjS6vQzhs9pucwgcUvhOEQwRqR4NEG+jnAajtKKmKyDn0/o9V5r3Mo/qLrXNblw3G/EhW5y1Su4OdY8r90bdrqwIDAQAB"
	res, err := GetPublicKey(&key.PublicKey)
	if err != nil {
		t.Errorf("GetPublicKey(KEY): Unexpected error: %v", err)
	}
	if res != exp {
		t.Errorf("GetPublicKey(KEY): expected %v, actual %v", exp, res)
	}
}
