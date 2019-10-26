package base64

import (
	"testing"

	"github.com/jafossum/go-auth-server/utils/logger"
)

// Important to not get nullpointer on logger!
func init() {
	logger.TestInit()
}

func TestCalibCanHandle(t *testing.T) {
	exp := "AQAB"
	in := 65537
	res := EncodeUint64ToString(uint64(in))
	if res != exp {
		t.Errorf("EncodeUint64ToString(%v): expected %v, actual %v", in, exp, res)
	}
}
