package dbservice

import (
	"fmt"

	"github.com/KaiserWerk/CertMaker/internal/entity"
)

// GetAllIssuers fetches all available issuers (root and intermediates)
func (ds *DBService) GetAllIssuers() ([]entity.Issuer, error) {
	issuers := make([]entity.Issuer, 0)
	result := ds.db.Find(&issuers)

	roots := make([]entity.Issuer, 0)
	for _, issuer := range issuers {
		if issuer.ParentIssuerID == 0 {
			roots = append(roots, issuer)
		}
	}

	for _, root := range roots {
		for _, issuer := range issuers {
			if issuer.ParentIssuerID == root.ID {
				root.Intermediates = append(root.Intermediates, issuer)
			}
		}
	}

	return roots, result.Error
}

// FindIssuer finds an issuer by the supplied criteria
func (ds *DBService) FindIssuer(cond string, args ...interface{}) (*entity.Issuer, error) {
	var issuer entity.Issuer
	result := ds.db.Where(cond, args).Find(&issuer)
	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no user found")
	}

	if issuer.SourceType == "filesystem" {

	} else if issuer.SourceType == "local_database" {

	}

	return &issuer, nil
}

// AddIssuer creates a new issuer entry in the database
func (ds *DBService) AddIssuer(issuer *entity.Issuer) error {
	res := ds.db.Create(issuer)
	return res.Error
}

// UpdateIssuer updates an issuer entry in the database using the ID from the struct with the values
// from the struct
func (ds *DBService) UpdateIssuer(issuer *entity.Issuer) error {
	res := ds.db.Save(issuer)
	return res.Error
}

// DeleteIssuer deletes a given issuer from the database
func (ds *DBService) DeleteIssuer(issuer *entity.Issuer) error {
	res := ds.db.Unscoped().Delete(issuer)
	return res.Error
}
