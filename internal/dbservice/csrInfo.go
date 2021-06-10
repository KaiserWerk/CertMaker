package dbservice

import "github.com/KaiserWerk/CertMaker/internal/entity"

func (ds *dbservice) AddCsrInfo(csr *entity.CsrInfo) error {
	res := ds.db.Create(csr)
	return res.Error
}
