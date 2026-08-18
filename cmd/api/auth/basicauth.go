package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"github.com/gin-gonic/gin"
)

//BasicAuthUser holds credentials for basic auth
type BasicAuthUser struct {
	Username string
	Password string
}

//BasicAuthProvider handles HTTP Basic Authentication
type BasicAuthProvider struct {
	realm string
	users map[string]*BasicAuthUser
}

//NewBasicAuthProvider creates a new basic auth provider with a realm name
func NewBasicAuthProvider(realm string)*BasicAuthProvider{
	return &BasicAuthProvider{
		realm:realm,
		users:make(map[string]*BasicAuthUser),
	}
}

//AddUser registers a user credential
func(ba *BasicAuthProvider)AddUser(username,password string){
	ba.users[username]=&BasicAuthUser{
		Username:username,
		Password:password,
	}
}

//RemoveUser removes a user credential
func(ba *BasicAuthProvider)RemoveUser(username string){
	delete(ba.users,username)
}

//Validate checks if the username/password combination is valid
//Uses constant-time comparison to prevent timing attacks
func(ba *BasicAuthProvider)Validate(username,password string)bool{
	user,exists:=ba.users[username]
	if !exists{
		return false
	}

	return subtle.ConstantTimeCompare([]byte(user.Password),[]byte(password))==1
}

//ParseAuthHeader extracts username and password from a Basic auth header
func ParseAuthHeader(authHeader string)(username,password string,ok bool){
	if !strings.HasPrefix(authHeader,"Basic "){
		return "","",false
	}

	decoded,err:=base64.StdEncoding.DecodeString(authHeader[6:])
	if err!=nil{
		return "","",false
	}

	parts:=strings.SplitN(string(decoded),":",2)
	if len(parts)!=2{
		return "","",false
	}

	return parts[0],parts[1],true
}

//Middleware returns a Gin middleware that validates HTTP Basic Auth credentials
func(ba *BasicAuthProvider)Middleware()gin.HandlerFunc{
	return func(c *gin.Context){
		authHeader:=c.GetHeader("Authorization")
		username,password,ok:=ParseAuthHeader(authHeader)
		if !ok{
			c.Header("WWW-Authenticate","Basic realm=\""+ba.realm+"\"")
			c.AbortWithStatusJSON(401,gin.H{"error":ErrMissingCredentials.Error()})
			return
		}

		if !ba.Validate(username,password){
			c.Header("WWW-Authenticate","Basic realm=\""+ba.realm+"\"")
			c.AbortWithStatusJSON(401,gin.H{"error":ErrUnauthorized.Error()})
			return
		}

		c.Set("basic_auth_user",username)
		c.Next()
	}
}
