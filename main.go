package main

import (
	"go-sentry/cmd/api/auth"
	"go-sentry/cmd/api/handlers"
	"go-sentry/cmd/api/models"
	"time"

	"github.com/gin-gonic/gin"
)

//AppUser is the application's user model
type AppUser struct{
	ID string `json:"id"`
	Username string `json:"username"`
	Email string `json:"email"`
	Age int `json:"age"`
}

//AppUserStore implements models.UserStore[AppUser]
type AppUserStore struct{
	users map[string]AppUser
	passwords map[string]string
}

func NewAppUserStore()*AppUserStore{
	return &AppUserStore{
		users:make(map[string]AppUser),
		passwords:make(map[string]string),
	}
}

func(s *AppUserStore)FindByID(id string)(AppUser,error){
	user,ok:=s.users[id]
	if !ok{
		return AppUser{},models.ErrNotFound
	}
	return user,nil
}

func(s *AppUserStore)FindByEmail(email string)(AppUser,error){
	for _,user:=range s.users{
		if user.Email==email{
			return user,nil
		}
	}
	return AppUser{},models.ErrNotFound
}

func(s *AppUserStore)Create(user AppUser)(AppUser,error){
	s.users[user.ID]=user
	return user,nil
}

func(s *AppUserStore)Update(user AppUser)(AppUser,error){
	s.users[user.ID]=user
	return user,nil
}

func(s *AppUserStore)Delete(id string)error{
	delete(s.users,id)
	return nil
}

func main(){
	// Initialize JWT provider
	jwtAuth:=auth.NewJWTProvider[AppUser](auth.JWTConfig{
		SecretKey:"your-secret-key-change-in-production",
		Expiry:15*time.Minute,
		RefreshExpiry:7*24*time.Hour,
		Issuer:"go-sentry",
	})

	// Initialize API key provider
	apiKeyAuth:=auth.NewAPIKeyProvider()

	// Initialize Basic Auth provider
	basicAuth:=auth.NewBasicAuthProvider("go-sentry")

	// Initialize Session provider
	sessionAuth:=auth.NewSessionProvider(auth.SessionConfig{
		CookieName:"session_id",
		CookiePath:"/",
		MaxAge:24*time.Hour,
	})

	// Initialize OAuth2 providers
	googleOAuth:=auth.NewGoogleOAuth2("client-id","client-secret","http://localhost:8080/auth/google/callback")
	githubOAuth:=auth.NewGitHubOAuth2("client-id","client-secret","http://localhost:8080/auth/github/callback")

	// User store
	userStore:=NewAppUserStore()

	// Initialize handlers
	authHandlers:=handlers.NewAuthHandlers(jwtAuth,userStore,func(user AppUser,pass string)bool{
		return pass=="password"
	})

	oauth2Google:=handlers.NewOAuth2Handlers(googleOAuth,jwtAuth,func(oa *auth.OAuth2User)(AppUser,error){
		return AppUser{ID:oa.ID,Username:oa.Name,Email:oa.Email},nil
	})

	oauth2GitHub:=handlers.NewOAuth2Handlers(githubOAuth,jwtAuth,func(oa *auth.OAuth2User)(AppUser,error){
		return AppUser{ID:oa.ID,Username:oa.Name,Email:oa.Email},nil
	})

	apiKeyHandlers:=handlers.NewAPIKeyHandlers(apiKeyAuth)

	// Setup Gin router
	r:=gin.Default()

	// Public routes
	r.POST("/register",authHandlers.Register())
	r.POST("/login",authHandlers.Login())
	r.POST("/refresh",authHandlers.RefreshToken())

	// OAuth2 routes
	r.GET("/auth/google",oauth2Google.Redirect())
	r.GET("/auth/google/callback",oauth2Google.Callback())
	r.GET("/auth/github",oauth2GitHub.Redirect())
	r.GET("/auth/github/callback",oauth2GitHub.Callback())

	// Protected routes (JWT)
	jwtProtected:=r.Group("/api",jwtAuth.Middleware())
	{
		jwtProtected.GET("/profile",authHandlers.Profile())
		jwtProtected.POST("/logout",authHandlers.Logout())
	}

	// Protected routes (API Key)
	apiKeyProtected:=r.Group("/api",apiKeyAuth.Middleware())
	{
		apiKeyProtected.POST("/api-keys",apiKeyAuth.Middleware(),apiKeyHandlers.GenerateKey())
		apiKeyProtected.DELETE("/api-keys/:hash",apiKeyAuth.Middleware(),apiKeyHandlers.RevokeKey())
		apiKeyProtected.GET("/api-keys",apiKeyAuth.Middleware(),apiKeyHandlers.ListKeys())
	}

	// Protected routes (Basic Auth)
	basicProtected:=r.Group("/api",basicAuth.Middleware())
	{
		basicProtected.GET("/basic/profile",authHandlers.Profile())
	}

	// Protected routes (Session)
	sessionProtected:=r.Group("/api",sessionAuth.Middleware())
	{
		sessionProtected.GET("/session/profile",authHandlers.Profile())
	}

	r.Run(":8080")
}
