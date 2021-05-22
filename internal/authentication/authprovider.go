package authentication

import "github.com/KaiserWerk/CertMaker/internal/entity"

type AuthProvider interface {
	AuthenticateUser(username string, password string) (*entity.User, error)
	DeAuthenticateUser(user *entity.User) error
}


