package dbservice

import "github.com/KaiserWerk/CertMaker/internal/entity"

func (ds *dbservice) AddCertInfo(cr *entity.CertInfo) error {
	res := ds.db.Create(cr)
	if res.Error != nil {
		return res.Error
	}

	return nil
}

func (ds *dbservice) GetAllCertInfo() ([]entity.CertInfo, error) {
	ci := make([]entity.CertInfo, 0)
	res := ds.db.Find(&ci)
	if res.Error != nil {
		return nil, res.Error
	}

	return ci, nil
}
