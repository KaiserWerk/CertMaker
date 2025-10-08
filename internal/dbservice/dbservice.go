package dbservice

import (
	"errors"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var (
	ErrNotFound = errors.New("record not found")
)

type DBService struct {
	db *gorm.DB
}

// New creates and returns a new database connection
func New(config *configuration.AppConfig) (*DBService, error) {
	var driver gorm.Dialector = mysql.Open(config.Database.DSN)
	if config.Database.Driver == "sqlite" {
		driver = sqlite.Open(config.Database.DSN)
	} else if config.Database.Driver == "pgsql" {
		driver = postgres.Open(config.Database.DSN)
	} else if config.Database.Driver == "mssql" {
		driver = sqlserver.Open(config.Database.DSN)
	}

	db, err := gorm.Open(driver, &gorm.Config{
		PrepareStmt: true,
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
			NoLowerCase:   false,
		},
	})
	if err != nil {
		return nil, err
	}

	return &DBService{db: db}, nil
}

// AutoMigrate makes sure the database schema
// is up-to-date.
func (ds *DBService) AutoMigrate() error {
	err := ds.db.AutoMigrate(
		&entity.CertInfo{},
		&entity.Challenge{},
		&entity.RequestInfo{},
		&entity.SystemSetting{},
		&entity.User{},
	)
	if err != nil {
		return err
	}

	return nil
}
