package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// FindIssuer finds an issuer by the supplied criteria
func (ds *DBService) FindIssuerLocalDatabaseSource(cond string, args ...interface{}) (*entity.IssuerLocalDatabaseSource, error) {
	var source entity.IssuerLocalDatabaseSource
	result := ds.db.Where(cond, args).Find(&source)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no source found")
	}

	return &source, nil
}

// AddIssuer creates a new issuer entry in the database
func (ds *DBService) AddIssuerLocalDatabaseSource(source *entity.IssuerLocalDatabaseSource) error {
	res := ds.db.Create(source)
	return res.Error
}

// DeleteIssuer deletes a given issuer from the database
func (ds *DBService) DeleteIssuerLocalDatabaseSource(source *entity.IssuerLocalDatabaseSource) error {
	res := ds.db.Unscoped().Delete(source)
	return res.Error
}
