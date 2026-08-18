package auth

import "errors"

var (
	//ErrTokenExpired indicates the token has expired
	ErrTokenExpired=errors.New("token has expired")

	//ErrInvalidToken indicates the token is malformed or invalid
	ErrInvalidToken=errors.New("invalid token")

	//ErrMissingCredentials indicates required credentials are missing
	ErrMissingCredentials=errors.New("missing credentials")

	//ErrUnauthorized indicates the user is not authenticated
	ErrUnauthorized=errors.New("unauthorized")

	//ErrForbidden indicates the user lacks required permissions
	ErrForbidden=errors.New("forbidden")

	//ErrInvalidAPIKey indicates the API key is invalid
	ErrInvalidAPIKey=errors.New("invalid API key")

	//ErrOAuthCodeMissing indicates the OAuth authorization code is missing
	ErrOAuthCodeMissing=errors.New("missing OAuth authorization code")

	//ErrOAuthStateMismatch indicates the OAuth state parameter doesn't match
	ErrOAuthStateMismatch=errors.New("OAuth state mismatch")

	//ErrSessionNotFound indicates the session does not exist
	ErrSessionNotFound=errors.New("session not found")

	//ErrSessionExpired indicates the session has expired
	ErrSessionExpired=errors.New("session has expired")
)
