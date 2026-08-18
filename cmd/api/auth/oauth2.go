package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

//OAuth2Config holds configuration for an OAuth2 provider
type OAuth2Config struct {
	ClientID string
	ClientSecret string
	RedirectURL string
	AuthURL string
	TokenURL string
	UserInfoURL string
	Scopes []string
}

//OAuth2Token represents the OAuth2 token response
type OAuth2Token struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope string `json:"scope"`
}

//OAuth2User represents user info from an OAuth2 provider
type OAuth2User struct {
	ID string `json:"id"`
	Email string `json:"email"`
	Name string `json:"name"`
	Picture string `json:"picture"`
	Provider string `json:"provider"`
}

//OAuth2Provider handles OAuth2 authentication flows
type OAuth2Provider struct {
	Config OAuth2Config
	HTTPClient *http.Client
}

//NewOAuth2Provider creates a new OAuth2 provider
func NewOAuth2Provider(cfg OAuth2Config)*OAuth2Provider{
	return &OAuth2Provider{
		Config:cfg,
		HTTPClient:&http.Client{Timeout:10*time.Second},
	}
}

//GetAuthURL generates the authorization URL to redirect the user to
func(oa *OAuth2Provider)GetAuthURL(state string)string{
	params:=url.Values{
		"client_id":{oa.Config.ClientID},
		"redirect_uri":{oa.Config.RedirectURL},
		"response_type":{"code"},
		"scope":{strings.Join(oa.Config.Scopes," ")},
		"state":{state},
	}
	return oa.Config.AuthURL+"?"+params.Encode()
}

//ExchangeCode exchanges an authorization code for an access token
func(oa *OAuth2Provider)ExchangeCode(code string)(*OAuth2Token,error){
	data:=url.Values{
		"grant_type":{"authorization_code"},
		"code":{code},
		"redirect_uri":{oa.Config.RedirectURL},
		"client_id":{oa.Config.ClientID},
		"client_secret":{oa.Config.ClientSecret},
	}

	resp,err:=oa.HTTPClient.Post(oa.Config.TokenURL,"application/x-www-form-urlencoded",strings.NewReader(data.Encode()))
	if err!=nil{
		return nil,fmt.Errorf("token request failed: %w",err)
	}
	defer resp.Body.Close()

	body,err:=io.ReadAll(resp.Body)
	if err!=nil{
		return nil,fmt.Errorf("failed to read token response: %w",err)
	}

	if resp.StatusCode!=http.StatusOK{
		return nil,fmt.Errorf("token exchange failed: %s",string(body))
	}

	var token OAuth2Token
	if err:=json.Unmarshal(body,&token);err!=nil{
		return nil,fmt.Errorf("failed to parse token response: %w",err)
	}

	return &token,nil
}

//GetUser fetches user info from the provider using the access token
func(oa *OAuth2Provider)GetUser(token *OAuth2Token)(*OAuth2User,error){
	req,err:=http.NewRequest("GET",oa.Config.UserInfoURL,nil)
	if err!=nil{
		return nil,fmt.Errorf("failed to create request: %w",err)
	}

	req.Header.Set("Authorization","Bearer "+token.AccessToken)

	resp,err:=oa.HTTPClient.Do(req)
	if err!=nil{
		return nil,fmt.Errorf("user info request failed: %w",err)
	}
	defer resp.Body.Close()

	body,err:=io.ReadAll(resp.Body)
	if err!=nil{
		return nil,fmt.Errorf("failed to read user info response: %w",err)
	}

	if resp.StatusCode!=http.StatusOK{
		return nil,fmt.Errorf("user info request failed: %s",string(body))
	}

	var user OAuth2User
	if err:=json.Unmarshal(body,&user);err!=nil{
		return nil,fmt.Errorf("failed to parse user info: %w",err)
	}

	return &user,nil
}

//HandleCallback processes the OAuth2 callback, exchanges code for token, and fetches user info
func(oa *OAuth2Provider)HandleCallback(code,state,expectedState string)(*OAuth2User,*OAuth2Token,error){
	if code==""{
		return nil,nil,ErrOAuthCodeMissing
	}
	if state!=expectedState{
		return nil,nil,ErrOAuthStateMismatch
	}

	token,err:=oa.ExchangeCode(code)
	if err!=nil{
		return nil,nil,err
	}

	user,err:=oa.GetUser(token)
	if err!=nil{
		return nil,nil,err
	}

	return user,token,nil
}

//Middleware returns a Gin middleware that validates OAuth2 bearer tokens
func(oa *OAuth2Provider)Middleware()gin.HandlerFunc{
	return func(c *gin.Context){
		tokenString,ok:=extractBearerToken(c)
		if !ok{
			c.AbortWithStatusJSON(401,gin.H{"error":ErrUnauthorized.Error()})
			return
		}

		c.Set("oauth2_token",tokenString)
		c.Next()
	}
}

//NewGoogleOAuth2 creates a pre-configured OAuth2 provider for Google
func NewGoogleOAuth2(clientID,clientSecret,redirectURL string)*OAuth2Provider{
	return NewOAuth2Provider(OAuth2Config{
		ClientID:clientID,
		ClientSecret:clientSecret,
		RedirectURL:redirectURL,
		AuthURL:"https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:"https://oauth2.googleapis.com/token",
		UserInfoURL:"https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:[]string{"openid","profile","email"},
	})
}

//NewGitHubOAuth2 creates a pre-configured OAuth2 provider for GitHub
func NewGitHubOAuth2(clientID,clientSecret,redirectURL string)*OAuth2Provider{
	return NewOAuth2Provider(OAuth2Config{
		ClientID:clientID,
		ClientSecret:clientSecret,
		RedirectURL:redirectURL,
		AuthURL:"https://github.com/login/oauth/authorize",
		TokenURL:"https://github.com/login/oauth/access_token",
		UserInfoURL:"https://api.github.com/user",
		Scopes:[]string{"user:email"},
	})
}
