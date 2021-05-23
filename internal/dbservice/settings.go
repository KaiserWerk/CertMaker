package dbservice

import (
	"errors"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"gorm.io/gorm"
)

func (ds *dbservice) GetAllSettings() (map[string]string, error) {
	settings := make([]entity.SystemSetting, 0)
	result := ds.db.Find(&settings)
	if result.Error != nil {
		return nil, result.Error
	}

	s := make(map[string]string)

	for _, v := range settings {
		s[v.Name] = v.Value
	}

	return s, nil
}

func (ds *dbservice) GetSetting(name string) (string, error) {
	var setting entity.SystemSetting
	result := ds.db.Where("name = ?", name).First(&setting)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", result.Error
	}

	return setting.Value, nil
}

func (ds *dbservice) SetSetting(name, value string) error {
	var setting entity.SystemSetting
	result := ds.db.Where("name = ?", name).First(&setting)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			s := entity.SystemSetting{
				Name:  name,
				Value: value,
			}

			r := ds.db.Create(&s)
			return r.Error
		}
		return result.Error
	}

	setting.Value = value

	result = ds.db.Save(&setting)
	return result.Error
}
