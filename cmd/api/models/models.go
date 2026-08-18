package models

import "github.com/golang-jwt/jwt/v5"


type Params[T any] struct{
	Password string `json:"-"`
	Data T `json:"data"`
}


//claims wraps the standard JWT registration and embeds the dynamic data type
type Claims[T any] struct{
	Data T `json:"data"` // This holds your custom username,emails,etc
	jwt.RegisteredClaims
}