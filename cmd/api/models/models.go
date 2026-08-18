package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//ErrNotFound indicates the requested resource was not found
var ErrNotFound=errors.New("not found")

//Params wraps input data with a password for auth registration/login
type Params[T any]struct{
	Password string `json:"-"`
	Data T `json:"data"`
}

//Claims wraps the standard JWT registration and embeds the dynamic data type
type Claims[T any]struct{
	Data T `json:"data"`
	jwt.RegisteredClaims
}

//LoginRequest is the standard login request body
type LoginRequest[T any]struct{
	Password string `json:"password" binding:"required"`
	Data T `json:"data" binding:"required"`
}

//RegisterRequest is the standard registration request body
type RegisterRequest[T any]struct{
	Password string `json:"password" binding:"required,min=8"`
	Data T `json:"data" binding:"required"`
}

//TokenPair holds an access token and refresh token
type TokenPair struct{
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenType string `json:"token_type"`
}

//RefreshRequest is the request body for token refresh
type RefreshRequest struct{
	RefreshToken string `json:"refresh_token" binding:"required"`
}

//AuthResponse is the standard auth response with tokens and user data
type AuthResponse[T any]struct{
	Tokens TokenPair `json:"tokens"`
	User T `json:"user"`
}

//ErrorResponse is the standard error response
type ErrorResponse struct{
	Error string `json:"error"`
	Message string `json:"message,omitempty"`
}

//UserStore defines the interface for user persistence
type UserStore[T any]interface{
	FindByID(id string)(T,error)
	FindByEmail(email string)(T,error)
	Create(user T)(T,error)
	Update(user T)(T,error)
	Delete(id string)error
}
