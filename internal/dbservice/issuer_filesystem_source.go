package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// FindIssuer finds an issuer by the supplied criteria
func (ds *DBService) FindIssuerFileSystemSource(cond string, args ...interface{}) (*entity.IssuerFileSystemSource, error) {
	var source entity.IssuerFileSystemSource
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
func (ds *DBService) AddIssuerFileSystemSource(source *entity.IssuerFileSystemSource) error {
	res := ds.db.Create(source)
	return res.Error
}

// DeleteIssuer deletes a given issuer from the database
func (ds *DBService) DeleteIssuerFileSystemSource(source *entity.IssuerFileSystemSource) error {
	res := ds.db.Unscoped().Delete(source)
	return res.Error
}
