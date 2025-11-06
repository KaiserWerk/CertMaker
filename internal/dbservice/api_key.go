package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// GetAPIKeysForUser just fetches all API keys for a user
func (ds *DBService) GetAPIKeysForUser(userID uint) ([]*entity.APIKey, error) {
	keys := make([]*entity.APIKey, 0)
	result := ds.db.Where("user_id = ?", userID).Find(&keys)

	return keys, result.Error
}

// FindAPIKey finds a user by the supplied criteria
func (ds *DBService) FindAPIKey(cond string, args ...interface{}) (*entity.APIKey, error) {
	var key entity.APIKey
	result := ds.db.Where(cond, args).Find(&key)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no key found")
	}

	return &key, nil
}

// AddAPIKey creates a new API key entry in the database
func (ds *DBService) AddAPIKey(key *entity.APIKey) error {
	res := ds.db.Create(key)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// UpdateAPIKey updates a user with the ID from the struct with the values
// from the struct
func (ds *DBService) UpdateAPIKey(key *entity.APIKey) error {
	res := ds.db.Save(key)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

// DeleteAPIKey deletes a given API key from the database
func (ds *DBService) DeleteAPIKey(key *entity.APIKey) error {
	res := ds.db.Unscoped().Delete(key)
	if res.Error != nil {
		return res.Error
	}

	return nil
}
