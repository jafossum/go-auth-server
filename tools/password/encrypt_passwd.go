package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const pwdMinLen = 6

// Encrypt and salt
// Reference https://medium.com/@jcox250/password-hash-salt-using-golang-b041dc94cb72
func main() {
	// Enter a password and generate a salted hash
	pwd := getConsoleInput("password")
	if pwd == "" {
		return
	}
	hash := hashAndSalt(pwd)
	fmt.Println("Salted Hash", hash)
}

func getConsoleInput(t string) string {
	// Prompt the user to enter a password
	fmt.Printf("Enter %s:\n", t)
	// Variable to store the users input
	var pwd string
	// Read the users input
	_, err := fmt.Scan(&pwd)
	if err != nil {
		log.Println(err)
		return ""
	}
	if len(pwd) < pwdMinLen {
		log.Printf("Password provided needs to be at leat %d characters long\n", pwdMinLen)
		return ""
	}
	// Return the users input as a byte slice which will save us
	// from having to do this conversion later on
	return pwd
}

func hashAndSalt(pwd string) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}
