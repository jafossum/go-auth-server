package passwd

import (
	"testing"

	"github.com/jafossum/go-auth-server/utils/logger"
)

// Important to not get nullpointer on logger!
func init() {
	logger.TestInit()
}

var PasswdHashSt = []struct {
	passwd   string // input
	expected bool   // expected result
}{
	{"Passwd", false},
	{"SomeOtheerPassWdThing", false},
	{"Short", true},
}

func TestHashAndSalt(t *testing.T) {
	for _, tc := range PasswdHashSt {
		t.Run(tc.passwd, func(t *testing.T) {
			tc := tc // rebind tc into this lexical scope
			t.Parallel()
			_, err := HashAndSalt(tc.passwd)
			if err != nil && !tc.expected {
				t.Errorf("HashAndSalt(%s) unexpected error expected %v, actual %v", tc.passwd, tc.expected, err)
			}
			if err == nil && tc.expected {
				t.Errorf("HashAndSalt(%s) unexpected error expected %v, actual %v", tc.passwd, tc.expected, err)
			}
		})
	}
}

var PasswdHashCmp = []struct {
	passwd   string // input
	hash     string // hashed passwd
	expected bool   // expected result
	err      bool   // error
}{
	{"Passwd", "$2a$10$B3Fu0P.r0KRmW4YIx22OAO1opL95XyjpHQF4MbFnVgcpS.BpQGpuS", true, false},
	{"SomeOtheerPassWdThing", "$2a$10$d5Ekr.5MRSnE7YxC3WAmE.gt9VhgsfYo.mPAGDrtFZXS2nCPtWqsS", true, false},
	{"MagickHash", "$2a$10$EOmsDTSMWZK6/HqnsybxP.bQ9PFl8peMI65RwsjWkmHx/edkNkEFO", true, false},
	{"PASSWD", "$2a$10$B3Fu0P.r0KRmW4YIx22OAO1opL95XyjpHQF4MbFnVgcpS.BpQGpuS", false, true},
	{"Passwd", "$2a$10$B3Fu0P.r0KRmW4HQF4MbFnVgcpS.BpQGpuS", false, true},
}

func TestComparePasswords(t *testing.T) {
	for _, tc := range PasswdHashCmp {
		t.Run(tc.passwd, func(t *testing.T) {
			tc := tc // rebind tc into this lexical scope
			t.Parallel()
			res, err := ComparePasswords(tc.passwd, tc.hash)
			if err != nil && !tc.err || err == nil && tc.err {
				t.Errorf("ComparePasswords(%s, %s) unexpected error expected %v, actual %v", tc.passwd, tc.hash, tc.expected, err)
			}
			if res != tc.expected {
				t.Errorf("ComparePasswords(%s, %s) unexpected error expected %v, actual %v", tc.passwd, tc.hash, tc.expected, err)
			}
		})
	}
}
