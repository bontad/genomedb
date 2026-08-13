// Command orchestrator runs the Server-Orchestrator: blind routing table,
// mutation seed dispatch, delta gossip. It never sees fragment content or
// keys — see orchestrator/orchestrator.go.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mutant-db/orchestrator"
)

func main() {
	addr := flag.String("addr", ":7001", "indirizzo di ascolto")
	interval := flag.Duration("mutation-interval", 20*time.Second, "intervallo base tra mutazioni pianificate")
	jitter := flag.Duration("mutation-jitter", 15*time.Second, "jitter casuale aggiunto all'intervallo")
	flag.Parse()

	o := orchestrator.New()
	o.MutationInterval = *interval
	o.MutationJitter = *jitter

	stop := make(chan struct{})
	go o.RunScheduledMutations(stop)

	srv := &http.Server{Addr: *addr, Handler: orchestrator.NewMux(o)}

	go func() {
		log.Printf("[orchestrator] in ascolto su %s (mutazioni ogni %s±%s)", *addr, *interval, *jitter)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[orchestrator] errore server: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("[orchestrator] arresto in corso...")
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
