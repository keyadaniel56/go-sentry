package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

//SessionData holds session state
type SessionData struct {
	SessionID string
	UserID string
	Data map[string]interface{}
	CreatedAt time.Time
	ExpiresAt time.Time
}

//SessionConfig holds configuration for session auth
type SessionConfig struct {
	CookieName string
	CookiePath string
	CookieDomain string
	CookieSecure bool
	CookieHTTPOnly bool
	MaxAge time.Duration
}

//SessionProvider handles cookie/session-based authentication
type SessionProvider struct {
	sessions map[string]*SessionData
	mu sync.RWMutex
	Config SessionConfig
}

//NewSessionProvider creates a new session provider with the given config
func NewSessionProvider(cfg SessionConfig)*SessionProvider{
	return &SessionProvider{
		sessions:make(map[string]*SessionData),
		Config:cfg,
	}
}

//CreateSession generates a new session and sets the cookie on the response
func(sp *SessionProvider)CreateSession(c *gin.Context,userID string,data map[string]interface{})error{
	sessionID,err:=generateSessionID()
	if err!=nil{
		return err
	}

	session:=&SessionData{
		SessionID:sessionID,
		UserID:userID,
		Data:data,
		CreatedAt:time.Now(),
		ExpiresAt:time.Now().Add(sp.Config.MaxAge),
	}

	sp.mu.Lock()
	sp.sessions[sessionID]=session
	sp.mu.Unlock()

	sp.setCookie(c,sessionID)
	return nil
}

//GetSession retrieves session data from the request cookie
func(sp *SessionProvider)GetSession(c *gin.Context)(*SessionData,error){
	sessionID,err:=c.Cookie(sp.Config.CookieName)
	if err!=nil||sessionID==""{
		return nil,ErrSessionNotFound
	}

	sp.mu.RLock()
	session,exists:=sp.sessions[sessionID]
	sp.mu.RUnlock()

	if !exists{
		return nil,ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt){
		sp.DestroySession(c)
		return nil,ErrSessionExpired
	}

	return session,nil
}

//DestroySession removes the session and clears the cookie
func(sp *SessionProvider)DestroySession(c *gin.Context){
	sessionID,_:=c.Cookie(sp.Config.CookieName)
	if sessionID!=""{
		sp.mu.Lock()
		delete(sp.sessions,sessionID)
		sp.mu.Unlock()
	}

	c.SetCookie(sp.Config.CookieName,"",-1,sp.Config.CookiePath,sp.Config.CookieDomain,sp.Config.CookieSecure,sp.Config.CookieHTTPOnly)
}

//RefreshSession extends the session expiry
func(sp *SessionProvider)RefreshSession(c *gin.Context)error{
	session,err:=sp.GetSession(c)
	if err!=nil{
		return err
	}

	sp.mu.Lock()
	session.ExpiresAt=time.Now().Add(sp.Config.MaxAge)
	sp.mu.Unlock()

	return nil
}

//GetUserID extracts the user ID from the session
func(sp *SessionProvider)GetUserID(c *gin.Context)(string,error){
	session,err:=sp.GetSession(c)
	if err!=nil{
		return "",err
	}
	return session.UserID,nil
}

//Middleware returns a Gin middleware that validates sessions from cookies
func(sp *SessionProvider)Middleware()gin.HandlerFunc{
	return func(c *gin.Context){
		session,err:=sp.GetSession(c)
		if err!=nil{
			c.AbortWithStatusJSON(401,gin.H{"error":err.Error()})
			return
		}

		c.Set("session",session)
		c.Set("user_id",session.UserID)
		c.Set("session_data",session.Data)
		c.Next()
	}
}

func(sp *SessionProvider)setCookie(c *gin.Context,sessionID string){
	c.SetCookie(
		sp.Config.CookieName,
		sessionID,
		int(sp.Config.MaxAge.Seconds()),
		sp.Config.CookiePath,
		sp.Config.CookieDomain,
		sp.Config.CookieSecure,
		sp.Config.CookieHTTPOnly,
	)
}

func generateSessionID()(string,error){
	bytes:=make([]byte,32)
	if _,err:=rand.Read(bytes);err!=nil{
		return "",err
	}
	return hex.EncodeToString(bytes),nil
}
