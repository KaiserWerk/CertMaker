package dbservice

import (
	"github.com/KaiserWerk/CertMaker/internal/entity"
	"github.com/KaiserWerk/CertMaker/internal/global"
	"github.com/KaiserWerk/CertMaker/internal/logging"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"sync"
)

type dbservice struct {
	db *gorm.DB
}

var (
	dbs    dbservice
	dbOnce sync.Once
)

// New creates and returns a new database connection
func New() *dbservice {
	dbOnce.Do(func() {
		var (
			config = global.GetConfiguration()
			logger = logging.GetLogger()
		)

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
			logger.Panic("gorm connection error: " + err.Error())
		}

		dbs = dbservice{db: db}
	})

	return &dbs
}

// AutoMigrate makes sure the database schema
// is up-to-date.
func (ds *dbservice) AutoMigrate() error {
	err := ds.db.AutoMigrate(
		&entity.CertInfo{},
		&entity.RequestInfo{},
		&entity.SystemSetting{},
		&entity.User{},
	)
	if err != nil {
		return err
	}

	return nil
}
