package models


type Params[T any] struct{
	Password string `json:"-"`
	Data T `json:"data"`
}