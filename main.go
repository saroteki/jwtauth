package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	rsaParser "github.com/srttk/jwt_test/rsa_parser"
)

var users = map[string]string{"naren": "passme", "admin": "password"}
type Response struct {
	Token string `json:"token"`
	Status string `json:"status"`
}

func ParseJwt(w http.ResponseWriter, r *http.Request) {
	tokenString, err := request.OAuth2Extractor.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return rsaParser.PublicKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied; Please check the access token"))
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		response := make(map[string]string)
		response["time"] = time.Now().String()
		response["user"] = claims["username"].(string)
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
	}
}

func GenerateJwt(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	name, ok := query["name"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "err. required name query")
		return
	}

	password, ok := query["password"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "err. required password query")
		return
	}
	claims := jwt.MapClaims {
		"name": name,
		"password": password,
		"exp":   time.Now().Add(time.Hour * 24 * 30).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(rsaParser.PrivateKey)
	if err != nil {
		fmt.Fprint(w, "token generate err")
		return
	}
	fmt.Fprint(w, tokenString)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/generate_jwt", GenerateJwt)
	r.HandleFunc("/parse_jwt", ParseJwt)
	http.ListenAndServe(":8080", r)
}
