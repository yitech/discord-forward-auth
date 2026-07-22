package main

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yitech/discord-forward-auth/internal/audit"
	"github.com/yitech/discord-forward-auth/internal/config"
	"github.com/yitech/discord-forward-auth/internal/discord"
	"github.com/yitech/discord-forward-auth/internal/httpapi"
	"github.com/yitech/discord-forward-auth/internal/mapping"
	"github.com/yitech/discord-forward-auth/internal/session"
	"github.com/yitech/discord-forward-auth/migrations"
)

//go:embed all:admin
var adminEmbed embed.FS

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config error", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Error("database ping failed", "err", err)
		os.Exit(1)
	}

	if err := migrations.Run(ctx, pool); err != nil {
		log.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	sessionStore := session.NewPostgresStore(pool)
	mappingStore := mapping.NewCachedStore(mapping.NewPostgresStore(pool), cfg.MappingCacheTTL)
	auditStore := audit.NewPostgresStore(pool)
	discordClient := discord.NewClient(cfg.DiscordClientID, cfg.DiscordClientSecret, cfg.RedirectURI())

	adminFS, err := fs.Sub(adminEmbed, "admin")
	if err != nil {
		log.Error("admin embed failed", "err", err)
		os.Exit(1)
	}

	srv := httpapi.New(cfg, sessionStore, mappingStore, auditStore, discordClient, adminFS, log)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := sessionStore.DeleteExpired(context.Background())
				if err != nil {
					log.Error("session cleanup failed", "err", err)
					continue
				}
				if n > 0 {
					log.Info("cleaned expired sessions", "count", n)
				}
			}
		}
	}()

	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "auth_host", cfg.AuthHost)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
