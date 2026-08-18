package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

//APIKeyInfo stores metadata about an API key
type APIKeyInfo struct {
	KeyHash string
	Name string
	UserID string
	Scopes []string
	ExpiresAt *time.Time
	CreatedAt time.Time
	Revoked bool
}

//APIKeyProvider handles API key authentication
type APIKeyProvider struct {
	keys map[string]*APIKeyInfo
	mu sync.RWMutex
 Header string
}

//NewAPIKeyProvider creates a new API key provider
func NewAPIKeyProvider()*APIKeyProvider{
	return &APIKeyProvider{
		keys:make(map[string]*APIKeyInfo),
		Header:"X-API-Key",
	}
}

//SetHeader sets the header name used to extract API keys
func(ak *APIKeyProvider)SetHeader(header string){
	ak.Header=header
}

//GenerateKey creates a new API key and stores its metadata
func(ak *APIKeyProvider)GenerateKey(name,userID string,scopes []string,expiresAt *time.Time)(string,*APIKeyInfo,error){
	rawKey,err:=generateRandomKey(32)
	if err!=nil{
		return "",nil,err
	}

	hash:=hashAPIKey(rawKey)

	info:=&APIKeyInfo{
		KeyHash:hash,
		Name:name,
		UserID:userID,
		Scopes:scopes,
		ExpiresAt:expiresAt,
		CreatedAt:time.Now(),
	}

	ak.mu.Lock()
	ak.keys[hash]=info
	ak.mu.Unlock()

	return rawKey,info,nil
}

//Validate checks if an API key is valid and returns its metadata
func(ak *APIKeyProvider)Validate(rawKey string)(*APIKeyInfo,error){
	hash:=hashAPIKey(rawKey)

	ak.mu.RLock()
	info,exists:=ak.keys[hash]
	ak.mu.RUnlock()

	if !exists{
		return nil,ErrInvalidAPIKey
	}

	if info.Revoked{
		return nil,ErrInvalidAPIKey
	}

	if info.ExpiresAt!=nil&&time.Now().After(*info.ExpiresAt){
		return nil,ErrTokenExpired
	}

	return info,nil
}

//RevokeKey marks an API key as revoked
func(ak *APIKeyProvider)RevokeKey(rawKey string)bool{
	hash:=hashAPIKey(rawKey)

	ak.mu.Lock()
	defer ak.mu.Unlock()

	info,exists:=ak.keys[hash]
	if !exists{
		return false
	}

	info.Revoked=true
	return true
}

//RevokeByKeyHash marks an API key as revoked by its hash
func(ak *APIKeyProvider)RevokeByKeyHash(hash string)bool{
	ak.mu.Lock()
	defer ak.mu.Unlock()

	info,exists:=ak.keys[hash]
	if !exists{
		return false
	}

	info.Revoked=true
	return true
}

//ListKeys returns all API key metadata (hashes only, not raw keys)
func(ak *APIKeyProvider)ListKeys()[]*APIKeyInfo{
	ak.mu.RLock()
	defer ak.mu.RUnlock()

	keys:=make([]*APIKeyInfo,0,len(ak.keys))
	for _,info:=range ak.keys{
		keys=append(keys,info)
	}
	return keys
}

//HasScope checks if the key info contains a specific scope
func(info *APIKeyInfo)HasScope(scope string)bool{
	for _,s:=range info.Scopes{
		if s==scope{
			return true
		}
	}
	return false
}

//Middleware returns a Gin middleware that validates API keys
func(ak *APIKeyProvider)Middleware()gin.HandlerFunc{
	return func(c *gin.Context){
		rawKey:=c.GetHeader(ak.Header)
		if rawKey==""{
			c.AbortWithStatusJSON(401,gin.H{"error":ErrMissingCredentials.Error()})
			return
		}

		info,err:=ak.Validate(rawKey)
		if err!=nil{
			c.AbortWithStatusJSON(401,gin.H{"error":err.Error()})
			return
		}

		c.Set("api_key_info",info)
		c.Set("user_id",info.UserID)
		c.Next()
	}
}

//ScopeMiddleware returns a middleware that checks for specific scopes
func(ak *APIKeyProvider)ScopeMiddleware(requiredScopes ...string)gin.HandlerFunc{
	return func(c *gin.Context){
		val,exists:=c.Get("api_key_info")
		if !exists{
			c.AbortWithStatusJSON(401,gin.H{"error":ErrUnauthorized.Error()})
			return
		}

		info,ok:=val.(*APIKeyInfo)
		if !ok{
			c.AbortWithStatusJSON(401,gin.H{"error":ErrUnauthorized.Error()})
			return
		}

		for _,required:=range requiredScopes{
			if !info.HasScope(required){
				c.AbortWithStatusJSON(403,gin.H{"error":ErrForbidden.Error()})
				return
			}
		}

		c.Next()
	}
}

func generateRandomKey(length int)(string,error){
	bytes:=make([]byte,length)
	if _,err:=rand.Read(bytes);err!=nil{
		return "",err
	}
	return hex.EncodeToString(bytes),nil
}

func hashAPIKey(key string)string{
	h:=sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
