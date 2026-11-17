package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Store struct {
	DB     *pgxpool.Pool
	logger *zap.Logger
}

type myQueryTracer struct {
	log *zap.Logger
}

func (tracer *myQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	sql := strings.ReplaceAll(data.SQL, "\n", " ")
	sql = strings.ReplaceAll(sql, "\t", "")
	sql = strings.TrimSpace(sql)
	tracer.log.Debug("executing query", zap.String("sql", sql), zap.Any("args", data.Args))
	return ctx
}

func (tracer *myQueryTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	tracer.log.Debug("finished executing query")
}

// New parses DSN and opens a pool. Errors never include the raw connection
// string (pgx may quote userinfo in its messages).
func New(logger *zap.Logger, DSN string) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(DSN)
	if err != nil {
		return nil, fmt.Errorf("unable to parse postgres DSN")
	}

	if logger.Core().Enabled(zapcore.DebugLevel) {
		poolConfig.ConnConfig.Tracer = &myQueryTracer{
			log: logger,
		}
	}

	db, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create postgres pool")
	}

	return &Store{DB: db, logger: logger}, nil
}

func (st *Store) Close() {

	st.DB.Close()

}
