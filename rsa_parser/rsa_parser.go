package rsa_parser

import (
	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

var PrivateKey *rsa.PrivateKey
var PublicKey *rsa.PublicKey

func init() {
	privateKey, err := lockupPrivateKey()
	if err != nil {
		panic("failed to parse jwt.rsa")
	}
	publicKey, err := lockupPublicKey()
	if err != nil {
		panic("failed to parse jwt.pub")
	}
	PrivateKey = privateKey
	PublicKey = publicKey
}

func lockupPrivateKey() (*rsa.PrivateKey, error) {
	rsaFile, err := ioutil.ReadFile("jwt.rsa")
	if err != nil {
		return nil, err
	}
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaFile)
	if err != nil {
		return nil, err
	}
	return parsedKey, nil
}

func lockupPublicKey() (*rsa.PublicKey, error) {
	rsaFile, err := ioutil.ReadFile("jwt.pub")
	if err != nil {
		return nil, err
	}
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(rsaFile)
	if err != nil {
		return nil, err
	}
	return parsedKey, nil
}