package dbservice

import "github.com/KaiserWerk/CertMaker/internal/entity"

func (ds *DBService) GetRequestInfo(id interface{}) (*entity.RequestInfo, error) {
	var ri entity.RequestInfo
	res := ds.db.First(&ri, id)

	return &ri, res.Error
}

func (ds *DBService) AddRequestInfo(ri *entity.RequestInfo) error {
	res := ds.db.Create(ri)
	return res.Error
}

func (ds *DBService) UpdateRequestInfo(ri *entity.RequestInfo) error {
	res := ds.db.Save(ri)
	return res.Error
}
