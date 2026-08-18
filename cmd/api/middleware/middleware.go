package middleware

import "github.com/gin-gonic/gin"

//SetUser stores user data in the gin context
func SetUser(c *gin.Context,key string,value interface{}){
	c.Set(key,value)
}

//GetUser retrieves user data from the gin context
func GetUser(c *gin.Context,key string)(interface{},bool){
	return c.Get(key)
}

//RequireScopes checks if the request has the required scopes from api_key_info
func RequireScopes(c *gin.Context,scopes []string)bool{
	val,exists:=c.Get("api_key_info")
	if !exists{
		return false
	}

	type scopeChecker interface{
		HasScope(string)bool
	}

	checker,ok:=val.(scopeChecker)
	if !ok{
		return false
	}

	for _,scope:=range scopes{
		if !checker.HasScope(scope){
			return false
		}
	}
	return true
}

//Chain combines multiple middleware into one
func Chain(middlewares ...gin.HandlerFunc)[]gin.HandlerFunc{
	return middlewares
}

//RespondError sends a standardized error JSON response
func RespondError(c *gin.Context,status int,err string,message string){
	c.AbortWithStatusJSON(status,gin.H{
		"error":err,
		"message":message,
	})
}
