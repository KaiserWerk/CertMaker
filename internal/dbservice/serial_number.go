package dbservice

import (
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"gorm.io/gorm"
)

func (db *DBService) GetOrCreateSerialNumber() (int64, error) {
	sn := &entity.SerialNumber{}
	result := db.db.First(sn, 1)
	if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
		sn.ID = 1
		sn.Value = 0
		result = db.db.Create(sn)
	}
	return sn.Value, result.Error
}

func (ds *DBService) IncrementSerialNumber(currentValue int64) (int64, error) {
	sn := &entity.SerialNumber{
		ID:    1,
		Value: currentValue,
	}

	sn.Value++
	if err := ds.db.Save(sn).Error; err != nil {
		return 0, err
	}

	return sn.Value, nil
}
