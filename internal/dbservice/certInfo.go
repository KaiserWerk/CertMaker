package dbservice

import (
	"fmt"
	"github.com/KaiserWerk/CertMaker/internal/entity"
)

func (ds *DBService) AddCertInfo(cr *entity.CertInfo) error {
	res := ds.db.Create(cr)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

func (ds *DBService) GetAllCertInfo() ([]entity.CertInfo, error) {
	ci := make([]entity.CertInfo, 0)
	res := ds.db.Find(&ci)
	if res.Error != nil {
		return nil, res.Error
	}

	return ci, nil
}

func (ds *DBService) FindCertInfo(cond string, args ...interface{}) (entity.CertInfo, error) {
	var ci entity.CertInfo
	result := ds.db.Where(cond, args).Find(&ci)
	if result.Error != nil {
		return entity.CertInfo{}, result.Error
	}

	if result.RowsAffected == 0 {
		return entity.CertInfo{}, fmt.Errorf("no cert info found")
	}

	return ci, nil
}

func (ds *DBService) UpdateCertInfo(ci *entity.CertInfo) error {
	res := ds.db.Save(ci)
	return res.Error
}
