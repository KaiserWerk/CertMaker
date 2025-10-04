package backup

import (
	"context"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/sqldump"
)

func StartMakingBackups(ctx context.Context, appConfig *configuration.AppConfig) {
	uploader := sqldump.NewUploader(
		appConfig.StorageBox.Username,
		appConfig.StorageBox.Password,
		appConfig.StorageBox.Host,
	)

	uploader.ScheduleUpload(
		ctx,
		sqldump.GetMySQLBackupFileByDSN(appConfig.Database.DSN, "certmaker"),
		true,
		".",
		3*time.Minute,
		7,
	)
}
