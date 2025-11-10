package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// GetAPIKeysForUser just fetches all API keys for a user
func (ds *DBService) GetAPIKeysForUser(userID any) ([]*entity.APIKey, error) {
	keys := make([]*entity.APIKey, 0)
	result := ds.db.Where("user_id = ?", userID).Find(&keys)

	return keys, result.Error
}

// FindAPIKey finds an API key for the specified user
func (ds *DBService) FindAPIKeyForUser(userID any, keyID any) (*entity.APIKey, error) {
	var apiKey entity.APIKey
	result := ds.db.Where("user_id = ? AND id = ?", userID, keyID).Find(&apiKey)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no key found")
	}

	return &apiKey, nil
}

// FindAPIKey finds an API key by the supplied criteria
func (ds *DBService) FindAPIKey(cond string, args ...interface{}) (*entity.APIKey, error) {
	var apiKey entity.APIKey
	result := ds.db.Where(cond, args).Find(&apiKey)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no key found")
	}

	return &apiKey, nil
}

// AddAPIKey creates a new API key entry in the database
func (ds *DBService) AddAPIKey(key *entity.APIKey) error {
	res := ds.db.Create(key)
	return res.Error
}

// UpdateAPIKey updates a user with the ID from the struct with the values
// from the struct
func (ds *DBService) UpdateAPIKey(key *entity.APIKey) error {
	res := ds.db.Save(key)
	return res.Error
}

// DeleteAPIKey deletes a given API key from the database
func (ds *DBService) DeleteAPIKey(key *entity.APIKey) error {
	res := ds.db.Unscoped().Delete(key)
	return res.Error
}
