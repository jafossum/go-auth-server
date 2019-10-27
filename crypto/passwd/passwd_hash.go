package passwd

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const pwdMinLen = 6

// HashAndSalt - Hash and salt password using bcrypt
func HashAndSalt(pwd string) (string, error) {
	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	if len(pwd) < pwdMinLen {
		return "", fmt.Errorf("Password provided needs to be at leat %d characters long", pwdMinLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePasswords - Validate password and hash
func ComparePasswords(plainPwd, hashedPwd string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(plainPwd))
}
