package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
)

var users = map[string]string{"naren": "passme", "admin": "password"}
type Response struct {
	Token string `json:"token"`
	Status string `json:"status"`
}

func init() {
	os.Setenv("SESSION_SECRET", "k;lasjdGRA:0923458jfkldls")
}

func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SESSION_SECRET")), nil
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

func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	if originalPassword, ok := users[username]; ok {
		if password == originalPassword {
			claims := jwt.MapClaims {
				"username": username,
				"ExpiresAt": 15000,
				"IssuedAt": time.Now().Unix(),
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(os.Getenv("SESSION_SECRET")))
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(err.Error()))
			}
			response := Response{Token: tokenString, Status: "success"}
			responseJSON, _ := json.Marshal(response)
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(responseJSON)
		} else {
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			return
		}
	} else {
		http.Error(w, "User is not found", http.StatusNotFound)
		return
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/getToken", getTokenHandler)
	r.HandleFunc("/healthcheck", HealthcheckHandler)
	http.Handle("/", r)
	srv := &http.Server{
		Handler: r,
		Addr: "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout: 15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
