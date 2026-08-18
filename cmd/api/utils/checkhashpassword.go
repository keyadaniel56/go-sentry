package utils

import "golang.org/x/crypto/bcrypt"


//CheckPasswordHash compares a row password against its stored
func CheckHashPassword(password, hash string)bool{
	err:=bcrypt.CompareHashAndPassword([]byte(hash),[]byte(password))
	return err==nil
}