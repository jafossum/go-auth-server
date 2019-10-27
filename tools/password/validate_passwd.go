package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const pwdMinLen = 6

func main() {
	// Enter password
	pwd := getConsoleInput("password")
	if pwd == "" {
		return
	}
	// Enter hash
	hash := getConsoleInput("hash")

	pwdMatch := comparePasswords(hash, pwd)
	fmt.Println("Passwords Match?", pwdMatch)
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
	}
	if len(pwd) < pwdMinLen {
		log.Printf("Password provided needs to be at leat %d characters long\n", pwdMinLen)
		return ""
	}
	// Return the users input as a byte slice which will save us
	// from having to do this conversion later on
	return pwd
}

func comparePasswords(hashedPwd, plainPwd string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPwd))
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
