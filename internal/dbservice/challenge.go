package dbservice

import (
	"github.com/KaiserWerk/CertMaker/internal/entity"
)

func (ds *DBService) FindChallenge(cond string, args ...interface{}) (*entity.Challenge, error) {
	var challenge entity.Challenge
	result := ds.db.Where(cond, args).Find(&challenge)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, ErrNotFound
	}

	return &challenge, nil
}

func (ds *DBService) AddChallenge(c *entity.Challenge) error {
	res := ds.db.Create(c)
	return res.Error
}

func (ds *DBService) DeleteChallenge(c *entity.Challenge) error {
	res := ds.db.Unscoped().Delete(c)
	return res.Error
}
