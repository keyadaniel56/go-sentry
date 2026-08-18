package auth

import (
	"errors"
	"go-sentry/cmd/api/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gin-gonic/gin"
)

//JWTConfig holds configuration for the JWT provider
type JWTConfig struct {
	SecretKey string
	Expiry time.Duration
	RefreshExpiry time.Duration
	Issuer string
}

//JWTProvider handles JWT token generation, validation, and refresh
type JWTProvider[T any]struct{
	Config JWTConfig
}

//NewJWTProvider creates a new JWT provider with the given configuration
func NewJWTProvider[T any](cfg JWTConfig)*JWTProvider[T]{
	return &JWTProvider[T]{Config:cfg}
}

//GenerateToken creates a signed JWT with the given user data
func(jp *JWTProvider[T])GenerateToken(userData T)(string,error){
	expirationTime:=time.Now().Add(jp.Config.Expiry)

	claims:=models.Claims[T]{
		Data:userData,
		RegisteredClaims:jwt.RegisteredClaims{
			ExpiresAt:jwt.NewNumericDate(expirationTime),
			IssuedAt:jwt.NewNumericDate(time.Now()),
			Issuer:jp.Config.Issuer,
		},
	}

	token:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	return token.SignedString([]byte(jp.Config.SecretKey))
}

//GenerateRefreshToken creates a long-lived refresh token
func(jp *JWTProvider[T])GenerateRefreshToken(userData T)(string,error){
	expirationTime:=time.Now().Add(jp.Config.RefreshExpiry)

	claims:=models.Claims[T]{
		Data:userData,
		RegisteredClaims:jwt.RegisteredClaims{
			ExpiresAt:jwt.NewNumericDate(expirationTime),
			IssuedAt:jwt.NewNumericDate(time.Now()),
			Issuer:jp.Config.Issuer,
		},
	}

	token:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	return token.SignedString([]byte(jp.Config.SecretKey))
}

//ValidateToken parses and validates a JWT string, returning the claims
func(jp *JWTProvider[T])ValidateToken(tokenString string)(*models.Claims[T],error){
	token,err:=jwt.ParseWithClaims(tokenString,&models.Claims[T]{},func(token *jwt.Token)(interface{},error){
		if _,ok:=token.Method.(*jwt.SigningMethodHMAC);!ok{
			return nil,ErrInvalidToken
		}
		return []byte(jp.Config.SecretKey),nil
	})
	if err!=nil{
		if errors.Is(err,jwt.ErrTokenExpired){
			return nil,ErrTokenExpired
		}
		return nil,ErrInvalidToken
	}

	claims,ok:=token.Claims.(*models.Claims[T])
	if !ok||!token.Valid{
		return nil,ErrInvalidToken
	}

	return claims,nil
}

//RefreshToken validates an existing token and issues a new one
func(jp *JWTProvider[T])RefreshToken(tokenString string)(string,error){
	claims,err:=jp.ValidateToken(tokenString)
	if err!=nil{
		return "",err
	}

	return jp.GenerateToken(claims.Data)
}

//GenerateTokenPair creates both an access token and refresh token
func(jp *JWTProvider[T])GenerateTokenPair(userData T)(accessToken,refreshToken string,err error){
	accessToken,err=jp.GenerateToken(userData)
	if err!=nil{
		return "","",err
	}

	refreshToken,err=jp.GenerateRefreshToken(userData)
	if err!=nil{
		return "","",err
	}

	return accessToken,refreshToken,nil
}

//Middleware returns a Gin middleware that validates JWT tokens from the Authorization header
func(jp *JWTProvider[T])Middleware()gin.HandlerFunc{
	return func(c *gin.Context){
		tokenString,ok:=extractBearerToken(c)
		if !ok{
			c.AbortWithStatusJSON(401,gin.H{"error":ErrUnauthorized.Error()})
			return
		}

		claims,err:=jp.ValidateToken(tokenString)
		if err!=nil{
			status:=401
			if errors.Is(err,ErrTokenExpired){
				status=401
			}
			c.AbortWithStatusJSON(status,gin.H{"error":err.Error()})
			return
		}

		c.Set("claims",claims)
		c.Set("user_data",claims.Data)
		c.Next()
	}
}

//extractBearerToken pulls the JWT from the Authorization: Bearer <token> header
func extractBearerToken(c *gin.Context)(string,bool){
	header:=c.GetHeader("Authorization")
	if len(header)<8||header[:7]!="Bearer "{
		return "",false
	}
	return header[7:],true
}

//GetClaims retrieves the typed claims from the gin context
func GetClaims[T any](c *gin.Context)(*models.Claims[T],bool){
	val,exists:=c.Get("claims")
	if !exists{
		return nil,false
	}
	claims,ok:=val.(*models.Claims[T])
	return claims,ok
}

//GetUserData retrieves the user data from the gin context
func GetUserData[T any](c *gin.Context)(T,bool){
	val,exists:=c.Get("user_data")
	if !exists{
		var zero T
		return zero,false
	}
	data,ok:=val.(T)
	return data,ok
}
