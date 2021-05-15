package dbservice

import (
	"github.com/KaiserWerk/SimpleCA/internal/entity"
	"github.com/KaiserWerk/SimpleCA/internal/global"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type dbservice struct {
	db *gorm.DB
}

func New() *dbservice {
	config := global.GetConfiguration()

	var driver gorm.Dialector = mysql.Open(config.Database.DSN)
	if config.Database.Driver == "sqlite" {
		driver = sqlite.Open(config.Database.DSN)
	}

	db, err := gorm.Open(driver, &gorm.Config{
		PrepareStmt: true,
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
			NoLowerCase:   false,
		},
	})
	if err != nil {
		panic("gorm connection error: " + err.Error())
	}

	return &dbservice{db: db}
}

func (ds dbservice) AutoMigrate() error {
	err := ds.db.AutoMigrate(
		&entity.CertInfo{},
		&entity.User{},
	)
	if err != nil {
		return err
	}

	return nil
}
