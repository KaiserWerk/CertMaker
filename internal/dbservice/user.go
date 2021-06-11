package dbservice

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// GetAllUsers just fetches all users
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

// AddUser creates a new user entry in the database
func (ds *dbservice) AddUser(u *entity.User) error {
	res := ds.db.Create(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// UpdateUser updates a user with the ID from the struct with the values
// from the struct
func (ds *dbservice) UpdateUser(u *entity.User) error {
	res := ds.db.Save(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// DeleteUser deletes a given user from the database
func (ds *dbservice) DeleteUser(u *entity.User) error {
	res := ds.db.Unscoped().Delete(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}
