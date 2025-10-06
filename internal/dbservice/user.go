package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// GetAllUsers just fetches all users
func (ds *DBService) GetAllUsers() ([]entity.User, error) {
	users := make([]entity.User, 0)
	result := ds.db.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}

	return users, nil
}

// FindUser finds a user by the supplied criteria
func (ds *DBService) FindUser(cond string, args ...interface{}) (*entity.User, error) {
	var user entity.User
	result := ds.db.Where(cond, args).Find(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no user found")
	}

	return &user, nil
}

// AddUser creates a new user entry in the database
func (ds *DBService) AddUser(u *entity.User) error {
	res := ds.db.Create(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// UpdateUser updates a user with the ID from the struct with the values
// from the struct
func (ds *DBService) UpdateUser(u *entity.User) error {
	res := ds.db.Save(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// DeleteUser deletes a given user from the database
func (ds *DBService) DeleteUser(u *entity.User) error {
	res := ds.db.Unscoped().Delete(u)
	if res.Error != nil {
		return res.Error
	}

	return nil
}
