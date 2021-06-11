package dbservice

import "github.com/KaiserWerk/CertMaker/internal/entity"

func (ds *dbservice) AddRequestInfo(ri *entity.RequestInfo) error {
	res := ds.db.Create(ri)
	return res.Error
}
