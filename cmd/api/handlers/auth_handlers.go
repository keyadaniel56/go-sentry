package handlers

import (
	"fmt"
	"go-sentry/cmd/api/auth"
	"go-sentry/cmd/api/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

//AuthHandlers provides ready-to-use Gin handlers for authentication
type AuthHandlers[T any]struct{
	JWT *auth.JWTProvider[T]
 SessionProvider *auth.SessionProvider
 UserStore models.UserStore[T]
 ValidateUser func(T,string)bool
}

//NewAuthHandlers creates a new AuthHandlers instance
func NewAuthHandlers[T any](jwt *auth.JWTProvider[T],store models.UserStore[T],validateFn func(T,string)bool)*AuthHandlers[T]{
	return &AuthHandlers[T]{
		JWT:jwt,
		UserStore:store,
		ValidateUser:validateFn,
	}
}

//Login handles POST /login with username/password
func(ah *AuthHandlers[T])Login()gin.HandlerFunc{
	return func(c *gin.Context){
		var req models.LoginRequest[T]
		if err:=c.ShouldBindJSON(&req);err!=nil{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:"invalid_request",
				Message:err.Error(),
			})
			return
		}

		user,err:=ah.UserStore.Create(req.Data)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"server_error",
				Message:"failed to process user",
			})
			return
		}

		if !ah.ValidateUser(user,req.Password){
			c.JSON(http.StatusUnauthorized,models.ErrorResponse{
				Error:auth.ErrUnauthorized.Error(),
			})
			return
		}

		accessToken,refreshToken,err:=ah.JWT.GenerateTokenPair(user)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"token_error",
				Message:"failed to generate token",
			})
			return
		}

		c.JSON(http.StatusOK,models.AuthResponse[T]{
			Tokens:models.TokenPair{
				AccessToken:accessToken,
				RefreshToken:refreshToken,
				ExpiresAt:time.Now().Add(ah.JWT.Config.Expiry),
				TokenType:"Bearer",
			},
			User:user,
		})
	}
}

//Register handles POST /register
func(ah *AuthHandlers[T])Register()gin.HandlerFunc{
	return func(c *gin.Context){
		var req models.RegisterRequest[T]
		if err:=c.ShouldBindJSON(&req);err!=nil{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:"invalid_request",
				Message:err.Error(),
			})
			return
		}

		user,err:=ah.UserStore.Create(req.Data)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"server_error",
				Message:"failed to create user",
			})
			return
		}

		accessToken,refreshToken,err:=ah.JWT.GenerateTokenPair(user)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"token_error",
				Message:"failed to generate token",
			})
			return
		}

		c.JSON(http.StatusCreated,models.AuthResponse[T]{
			Tokens:models.TokenPair{
				AccessToken:accessToken,
				RefreshToken:refreshToken,
				ExpiresAt:time.Now().Add(ah.JWT.Config.Expiry),
				TokenType:"Bearer",
			},
			User:user,
		})
	}
}

//RefreshToken handles POST /refresh
func(ah *AuthHandlers[T])RefreshToken()gin.HandlerFunc{
	return func(c *gin.Context){
		var req models.RefreshRequest
		if err:=c.ShouldBindJSON(&req);err!=nil{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:"invalid_request",
				Message:err.Error(),
			})
			return
		}

		accessToken,err:=ah.JWT.RefreshToken(req.RefreshToken)
		if err!=nil{
			c.JSON(http.StatusUnauthorized,models.ErrorResponse{
				Error:err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK,gin.H{
			"access_token":accessToken,
			"token_type":"Bearer",
		})
	}
}

//Profile handles GET /profile - returns the authenticated user's data
func(ah *AuthHandlers[T])Profile()gin.HandlerFunc{
	return func(c *gin.Context){
		user,exists:=auth.GetUserData[T](c)
		if !exists{
			c.JSON(http.StatusUnauthorized,models.ErrorResponse{
				Error:auth.ErrUnauthorized.Error(),
			})
			return
		}

		c.JSON(http.StatusOK,gin.H{"user":user})
	}
}

//Logout handles POST /logout
func(ah *AuthHandlers[T])Logout()gin.HandlerFunc{
	return func(c *gin.Context){
		if ah.SessionProvider!=nil{
			ah.SessionProvider.DestroySession(c)
		}

		c.JSON(http.StatusOK,gin.H{"message":"logged out"})
	}
}

//OAuth2Handlers provides handlers for OAuth2 authentication flows
type OAuth2Handlers[T any]struct{
	Provider *auth.OAuth2Provider
	JWT *auth.JWTProvider[T]
	StateStore map[string]bool
	GetUserFromOAuth func(*auth.OAuth2User)(T,error)
}

//NewOAuth2Handlers creates new OAuth2 handlers
func NewOAuth2Handlers[T any](provider *auth.OAuth2Provider,jwt *auth.JWTProvider[T],getUserFn func(*auth.OAuth2User)(T,error))*OAuth2Handlers[T]{
	return &OAuth2Handlers[T]{
		Provider:provider,
		JWT:jwt,
		StateStore:make(map[string]bool),
		GetUserFromOAuth:getUserFn,
	}
}

//Redirect handles GET /auth/<provider> - redirects to OAuth2 provider
func(oa *OAuth2Handlers[T])Redirect()gin.HandlerFunc{
	return func(c *gin.Context){
		state:=fmt.Sprintf("%d",time.Now().UnixNano())
		oa.StateStore[state]=true

		authURL:=oa.Provider.GetAuthURL(state)
		c.Redirect(http.StatusTemporaryRedirect,authURL)
	}
}

//Callback handles GET /auth/<provider>/callback - processes the OAuth2 callback
func(oa *OAuth2Handlers[T])Callback()gin.HandlerFunc{
	return func(c *gin.Context){
		code:=c.Query("code")
		state:=c.Query("state")

		expectedState:=state
		if !oa.StateStore[state]{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:auth.ErrOAuthStateMismatch.Error(),
			})
			return
		}
		delete(oa.StateStore,state)

		user,_,err:=oa.Provider.HandleCallback(code,state,expectedState)
		if err!=nil{
			c.JSON(http.StatusUnauthorized,models.ErrorResponse{
				Error:err.Error(),
			})
			return
		}

		appUser,err:=oa.GetUserFromOAuth(user)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"user_mapping_error",
				Message:"failed to map OAuth user",
			})
			return
		}

		accessToken,refreshToken,err:=oa.JWT.GenerateTokenPair(appUser)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"token_error",
			})
			return
		}

		c.JSON(http.StatusOK,models.AuthResponse[T]{
			Tokens:models.TokenPair{
				AccessToken:accessToken,
				RefreshToken:refreshToken,
				ExpiresAt:time.Now().Add(oa.JWT.Config.Expiry),
				TokenType:"Bearer",
			},
			User:appUser,
		})
	}
}

//APIKeyHandlers provides handlers for API key management
type APIKeyHandlers struct{
	Provider *auth.APIKeyProvider
}

//NewAPIKeyHandlers creates new API key handlers
func NewAPIKeyHandlers(provider *auth.APIKeyProvider)*APIKeyHandlers{
	return &APIKeyHandlers{Provider:provider}
}

//GenerateKeyRequest is the request body for API key generation
type GenerateKeyRequest struct{
	Name string `json:"name" binding:"required"`
	Scopes []string `json:"scopes"`
	ExpiresInHours int `json:"expires_in_hours"`
}

//GenerateKey handles POST /api-keys
func(akh *APIKeyHandlers)GenerateKey()gin.HandlerFunc{
	return func(c *gin.Context){
		var req GenerateKeyRequest
		if err:=c.ShouldBindJSON(&req);err!=nil{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:"invalid_request",
				Message:err.Error(),
			})
			return
		}

		userID,_:=c.Get("user_id")
		userIDStr,ok:=userID.(string)
		if !ok{
			userIDStr="anonymous"
		}

		var expiresAt *time.Time
		if req.ExpiresInHours>0{
			t:=time.Now().Add(time.Duration(req.ExpiresInHours)*time.Hour)
			expiresAt=&t
		}

		rawKey,_,err:=akh.Provider.GenerateKey(req.Name,userIDStr,req.Scopes,expiresAt)
		if err!=nil{
			c.JSON(http.StatusInternalServerError,models.ErrorResponse{
				Error:"key_generation_error",
			})
			return
		}

		c.JSON(http.StatusCreated,gin.H{
			"api_key":rawKey,
			"name":req.Name,
			"scopes":req.Scopes,
			"message":"Store this key securely. It will not be shown again.",
		})
	}
}

//RevokeKey handles DELETE /api-keys/:hash
func(akh *APIKeyHandlers)RevokeKey()gin.HandlerFunc{
	return func(c *gin.Context){
		hash:=c.Param("hash")
		if hash==""{
			c.JSON(http.StatusBadRequest,models.ErrorResponse{
				Error:"missing_key_hash",
			})
			return
		}

		if !akh.Provider.RevokeByKeyHash(hash){
			c.JSON(http.StatusNotFound,models.ErrorResponse{
				Error:"key_not_found",
			})
			return
		}

		c.JSON(http.StatusOK,gin.H{"message":"key revoked"})
	}
}

//ListKeys handles GET /api-keys
func(akh *APIKeyHandlers)ListKeys()gin.HandlerFunc{
	return func(c *gin.Context){
		keys:=akh.Provider.ListKeys()
		c.JSON(http.StatusOK,gin.H{"keys":keys})
	}
}
