package dbservice

import "github.com/KaiserWerk/CertMaker/internal/entity"

func (ds *dbservice) GetRequestInfo(id interface{}) (entity.RequestInfo, error) {
	var ri entity.RequestInfo
	res := ds.db.First(&ri, id)

	return ri, res.Error
}

func (ds *dbservice) AddRequestInfo(ri *entity.RequestInfo) error {
	res := ds.db.Create(ri)
	return res.Error
}

func (ds *dbservice) UpdateRequestInfo(ri *entity.RequestInfo) error {
	res := ds.db.Save(ri)
	return res.Error
}
