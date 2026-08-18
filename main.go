package main

import (
	"fmt"
	"go-sentry/cmd/api/models"
)



type AppUser struct{
	Username string `json:"username"`
	Email string `json:"email"`
	Age int `json:"age"`
}


func main(){
	input:=models.Params[AppUser]{
		Password: "password",
		Data: AppUser{
			Username: "cdk",
			Email: "test@cdk",
			Age: 30,
		},
	}

	fmt.Println(input.Password,input.Data.Username)
}