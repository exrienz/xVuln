package db

import "database/sql"

// Rows wraps sql.Rows for handler use
type Rows = sql.Rows

// QueryRows executes a raw SQL query string (intentionally unsafe for benchmarking)
func QueryRows(query string, args ...interface{}) (*sql.Rows, error) {
	return DB.Query(query, args...)
}
