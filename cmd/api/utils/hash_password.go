package utils

import "golang.org/x/crypto/bcrypt"




//HashPassword converts a plain text password into a secure bcrypt hash
func HashPassword(password string)(string,error){
	byte,err:=bcrypt.GenerateFromPassword([]byte(password),bcrypt.DefaultCost)
	return  string(byte),err
}