package auth

import (
	"go-sentry/cmd/api/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)



func GenerateToken[T any](userData T, expiry time.Duration, secretKey string)(string,error){
	expirationTime:=time.Now().Add(expiry)

	claims:=models.Claims[T]{
		Data: userData,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	return  token.SignedString([]byte(secretKey))
}