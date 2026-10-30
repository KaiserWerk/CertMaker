package certmaker

import (
	"sync"

	"github.com/KaiserWerk/CertMaker/internal/dbservice"
)

type DBSerialNumberGenerator struct {
	db  *dbservice.DBService
	mut *sync.Mutex
}

func NewDBSerialNumberGenerator(db *dbservice.DBService) *DBSerialNumberGenerator {
	return &DBSerialNumberGenerator{
		db:  db,
		mut: &sync.Mutex{},
	}
}

func (sng *DBSerialNumberGenerator) Next() (int64, error) {
	sng.mut.Lock()
	defer sng.mut.Unlock()

	currentValue, err := sng.db.GetOrCreateSerialNumber()
	if err != nil {
		return 0, err
	}

	newValue, err := sng.db.IncrementSerialNumber(currentValue)
	if err != nil {
		return 0, err
	}

	return newValue, nil
}
