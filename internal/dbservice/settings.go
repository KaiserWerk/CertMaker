package dbservice

import (
	"errors"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"gorm.io/gorm"
)

// GetAllSettings fetches a map[string]string containing all
// available settings
func (ds *DBService) GetAllSettings() (map[string]string, error) {
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

// GetSetting fetches the setting with the given name. If it does not exist,
// an empty string is returned instead of an error
func (ds *DBService) GetSetting(name string) string {
	var setting entity.SystemSetting
	result := ds.db.Where("name = ?", name).First(&setting)
	if result.Error != nil {
		return ""
	}

	return setting.Value
}

// SetSetting sets a setting with the name name to the value value
func (ds *DBService) SetSetting(name, value string) error {
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
