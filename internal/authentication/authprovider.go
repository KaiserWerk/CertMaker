package authentication

import "github.com/KaiserWerk/CertMaker/internal/entity"

type AuthProvider interface {
	AuthenticateUser(username string, password string) (*entity.User, error)
	DeAuthenticateUser(user *entity.User) error
	RegisterUser(user *entity.User) (int64, error)
	UpdateUser(user *entity.User) error
	RemoveUser(user *entity.User) error
}


