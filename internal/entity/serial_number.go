package entity

type SerialNumber struct {
	ID    int64 `gorm:"primaryKey"`
	Value int64
}