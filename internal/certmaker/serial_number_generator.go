package certmaker

type SerialNumberGenerator interface {
	Next() (int64, error)
}
