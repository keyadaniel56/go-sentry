# go-sentry

A reusable Go authentication package for Gin APIs. Drop-in auth with JWT, OAuth2, API keys, Basic Auth, and session-based authentication. Generic, composable, and ready to use.

## Features

- **JWT** -- Access + refresh token pairs, validation, token refresh
- **OAuth2** -- Pre-configured for Google and GitHub, custom provider support
- **API Key** -- SHA-256 hashed keys, scoped permissions, revocation
- **Basic Auth** -- Constant-time password comparison, WWW-Authenticate support
- **Session** -- Cookie-based sessions with expiry and refresh
- **Generic types** -- Works with any user model (`[T any]`)
- **Ready-to-use handlers** -- Login, register, logout, refresh, OAuth2 callbacks, API key CRUD
- **Gin middleware** -- Each auth type ships its own `Middleware()` for route groups

## Installation

```bash
go get go-sentry
```

## Quick Start

```go
package main

import (
    "go-sentry/cmd/api/auth"
    "go-sentry/cmd/api/handlers"
    "go-sentry/cmd/api/models"
    "time"

    "github.com/gin-gonic/gin"
)

type User struct {
    ID       string `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
}

// Implement models.UserStore[User]
type UserStore struct { /* ... */ }

func main() {
    jwtAuth := auth.NewJWTProvider[User](auth.JWTConfig{
        SecretKey:    "your-secret-key",
        Expiry:       15 * time.Minute,
        RefreshExpiry: 7 * 24 * time.Hour,
    })

    userStore := NewUserStore()

    h := handlers.NewAuthHandlers(jwtAuth, userStore, func(u User, pass string) bool {
        return pass == "correct-password"
    })

    r := gin.Default()

    r.POST("/register", h.Register())
    r.POST("/login", h.Login())
    r.POST("/refresh", h.RefreshToken())

    // Protected routes
    protected := r.Group("/api", jwtAuth.Middleware())
    protected.GET("/profile", h.Profile())

    r.Run(":8080")
}
```

## Auth Types

### JWT

Full access + refresh token flow with generic user data embedded in claims.

```go
jwtAuth := auth.NewJWTProvider[User](auth.JWTConfig{
    SecretKey:     "your-secret-key",
    Expiry:        15 * time.Minute,
    RefreshExpiry: 7 * 24 * time.Hour,
    Issuer:        "my-app",
})

// Generate tokens
accessToken, refreshToken, err := jwtAuth.GenerateTokenPair(user)

// Validate a token
claims, err := jwtAuth.ValidateToken(tokenString)
user := claims.Data // your User struct

// Refresh
newToken, err := jwtAuth.RefreshToken(refreshToken)

// Middleware
router.Use(jwtAuth.Middleware())

// Extract user data in handlers
user, exists := auth.GetUserData[User](c)
```

### OAuth2

Pre-configured for Google and GitHub. Custom providers use `NewOAuth2Provider`.

```go
google := auth.NewGoogleOAuth2("client-id", "client-secret", "http://localhost:8080/auth/google/callback")
github := auth.NewGitHubOAuth2("client-id", "client-secret", "http://localhost:8080/auth/github/callback")

// Redirect to provider
r.GET("/auth/google", func(c *gin.Context) {
    state := "random-state-string"
    url := google.GetAuthURL(state)
    c.Redirect(302, url)
})

// Handle callback
r.GET("/auth/google/callback", func(c *gin.Context) {
    code := c.Query("code")
    state := c.Query("state")

    user, token, err := google.HandleCallback(code, state, expectedState)
    // user is *auth.OAuth2User with ID, Email, Name, Picture
})

// Custom provider
custom := auth.NewOAuth2Provider(auth.OAuth2Config{
    ClientID:     "id",
    ClientSecret: "secret",
    RedirectURL:  "http://localhost:8080/callback",
    AuthURL:      "https://example.com/authorize",
    TokenURL:     "https://example.com/token",
    UserInfoURL:  "https://example.com/userinfo",
    Scopes:       []string{"profile", "email"},
})
```

Handlers are also available for the full OAuth2 flow:

```go
oauth2Google := handlers.NewOAuth2Handlers(google, jwtAuth, func(oa *auth.OAuth2User) (User, error) {
    return User{ID: oa.ID, Username: oa.Name, Email: oa.Email}, nil
})

r.GET("/auth/google", oauth2Google.Redirect())
r.GET("/auth/google/callback", oauth2Google.Callback())
```

### API Key

SHA-256 hashed keys with scoped permissions, expiry, and revocation.

```go
apiKeyAuth := auth.NewAPIKeyProvider()
apiKeyAuth.SetHeader("X-API-Key") // default is X-API-Key

// Generate a key
rawKey, info, err := apiKeyAuth.GenerateKey("my-key", "user-123", []string{"read", "write"}, &expiresAt)
// rawKey is shown once, then only the hash is stored

// Validate
info, err := apiKeyAuth.Validate(rawKey)

// Revoke
apiKeyAuth.RevokeKey(rawKey)
apiKeyAuth.RevokeByKeyHash(info.KeyHash)

// Check scopes
info.HasScope("read")

// Middleware
r.Use(apiKeyAuth.Middleware())

// Scope-restricted middleware
r.GET("/admin", apiKeyAuth.Middleware(), apiKeyAuth.ScopeMiddleware("admin"), handler)
```

Handlers for key management:

```go
kh := handlers.NewAPIKeyHandlers(apiKeyAuth)
r.POST("/api-keys", kh.GenerateKey())       // create key
r.GET("/api-keys", kh.ListKeys())           // list all keys
r.DELETE("/api-keys/:hash", kh.RevokeKey()) // revoke by hash
```

### Basic Auth

HTTP Basic Authentication with constant-time password comparison.

```go
basicAuth := auth.NewBasicAuthProvider("my-realm")
basicAuth.AddUser("admin", "password123")
basicAuth.AddUser("user", "secret")

// Manual validation
valid := basicAuth.Validate("admin", "password123")

// Parse header manually
username, password, ok := auth.ParseAuthHeader(authHeader)

// Middleware (sets "basic_auth_user" in context)
r.Use(basicAuth.Middleware())

// Access username in handler
username := c.GetString("basic_auth_user")
```

### Session

Cookie-based session management with in-memory store.

```go
sessionAuth := auth.NewSessionProvider(auth.SessionConfig{
    CookieName:    "session_id",
    CookiePath:    "/",
    CookieDomain:  "localhost",
    CookieSecure:  false,
    CookieHTTPOnly: true,
    MaxAge:        24 * time.Hour,
})

// Create session (sets cookie on response)
sessionAuth.CreateSession(c, "user-123", map[string]interface{}{
    "role": "admin",
})

// Get session
session, err := sessionAuth.GetSession(c)
// session.UserID, session.Data

// Destroy session (clears cookie)
sessionAuth.DestroySession(c)

// Refresh session expiry
sessionAuth.RefreshSession(c)

// Middleware (sets "session", "user_id", "session_data" in context)
r.Use(sessionAuth.Middleware())
```

## Handlers

Ready-to-use Gin handlers with generic types:

```go
h := handlers.NewAuthHandlers(jwtAuth, userStore, validateFn)

r.POST("/register", h.Register())       // POST body: { "password": "...", "data": { ... } }
r.POST("/login", h.Login())             // returns tokens + user
r.POST("/refresh", h.RefreshToken())    // POST body: { "refresh_token": "..." }
r.GET("/profile", jwtAuth.Middleware(), h.Profile())
r.POST("/logout", h.Logout())
```

### Response Format

```json
{
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "expires_at": "2026-01-01T00:00:00Z",
    "token_type": "Bearer"
  },
  "user": {
    "id": "1",
    "username": "cdk",
    "email": "test@example.com"
  }
}
```

### Error Format

```json
{
  "error": "unauthorized",
  "message": "optional details"
}
```

## UserStore Interface

Implement this interface to plug in your database:

```go
type UserStore[T any] interface {
    FindByID(id string) (T, error)
    FindByEmail(email string) (T, error)
    Create(user T) (T, error)
    Update(user T) (T, error)
    Delete(id string) error
}
```

## Middleware Helpers

```go
import "go-sentry/cmd/api/middleware"

// Store/retrieve user data
middleware.SetUser(c, "key", value)
val, ok := middleware.GetUser(c, "key")

// Check scopes on API key
if !middleware.RequireScopes(c, []string{"read", "write"}) {
    middleware.RespondError(c, 403, "forbidden", "missing required scopes")
    return
}
```

## Password Utilities

```go
import "go-sentry/cmd/api/utils"

// Hash a password (bcrypt)
hash, err := utils.HashPassword("my-password")

// Verify a password against a hash
valid := utils.CheckHashPassword("my-password", hash)
```

## Error Types

All errors are available in the `auth` package:

| Error | Description |
|---|---|
| `ErrTokenExpired` | JWT has expired |
| `ErrInvalidToken` | Malformed or invalid JWT |
| `ErrMissingCredentials` | Required credentials not provided |
| `ErrUnauthorized` | User not authenticated |
| `ErrForbidden` | User lacks required permissions |
| `ErrInvalidAPIKey` | API key not found or revoked |
| `ErrOAuthCodeMissing` | Authorization code missing from callback |
| `ErrOAuthStateMismatch` | CSRF state parameter mismatch |
| `ErrSessionNotFound` | Session does not exist |
| `ErrSessionExpired` | Session has expired |

## Project Structure

```
cmd/api/
├── auth/
│   ├── errors.go       # Custom error types
│   ├── jwt.go          # JWT provider
│   ├── oauth2.go       # OAuth2 provider (Google, GitHub)
│   ├── apikey.go       # API key provider
│   ├── basicauth.go    # Basic Auth provider
│   └── session.go      # Session provider
├── handlers/
│   └── auth_handlers.go  # Gin handlers
├── middleware/
│   └── middleware.go      # Context helpers
├── models/
│   └── models.go         # Shared types
└── utils/
    ├── hash_password.go
    └── checkhashpassword.go
```

## License

MIT
