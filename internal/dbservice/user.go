package dbservice

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/entity"
)

func (ds *dbservice) GetAllUsers() ([]entity.User, error) {
	users := make([]entity.User, 0)
	result := ds.db.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}

	return users, nil
}

// FindUser finds a user by the supplied criteria
func (ds *dbservice) FindUser(cond string, args ...interface{}) (entity.User, error) {
	var user entity.User
	result := ds.db.Where(cond, args).Find(&user)
	if result.Error != nil {
		return entity.User{}, result.Error
	}

	if result.RowsAffected == 0 {
		return entity.User{}, fmt.Errorf("no user found")
	}

	return user, nil
}

func (ds *dbservice) AddUser(u *entity.User) error {
	res := ds.db.Create(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

func (ds *dbservice) UpdateUser(u *entity.User) error {
	res := ds.db.Save(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

func (ds *dbservice) DeleteUser(u *entity.User) error {
	res := ds.db.Unscoped().Delete(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

