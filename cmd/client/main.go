// Command client runs a Client-Node daemon: it registers with the
// orchestrator, serves its P2P peer endpoints, runs the local watchdog,
// and exposes a small interactive command line for the demo (store /
// reconstruct / simulate-attack / status).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mutant-db/client"
	mcrypto "mutant-db/crypto"
	"mutant-db/mesh"
	"mutant-db/store"
)

func main() {
	nodeID := flag.String("node-id", "", "identificativo del nodo (obbligatorio)")
	peerAddr := flag.String("peer-addr", ":9001", "indirizzo TCP su cui questo nodo ascolta i pari (host:porta)")
	publicEndpoint := flag.String("public-endpoint", "", "URL con cui gli altri nodi raggiungono questo nodo (default: http://localhost<peer-addr>)")
	orchestratorURL := flag.String("orchestrator", "http://localhost:7001", "URL del server-orchestratore")
	dataDir := flag.String("data-dir", "", "cartella dati del nodo (default: ./data/<node-id>)")
	meshOnly := flag.Bool("mesh-only", false, "non registrarsi presso alcun orchestratore: nodo puro host di backup per la mesh fidata (es. il dispositivo di un familiare)")
	healInterval := flag.Duration("heal-interval", 30*time.Second, "intervallo del ciclo di auto-guarigione dei backup")
	healMargin := flag.Int("heal-margin", 1, "margine sopra la soglia prima che l'auto-guarigione intervenga")
	flag.Parse()

	if *nodeID == "" {
		fmt.Fprintln(os.Stderr, "errore: -node-id è obbligatorio")
		os.Exit(1)
	}
	endpoint := *publicEndpoint
	if endpoint == "" {
		endpoint = "http://localhost" + *peerAddr
	}
	dir := *dataDir
	if dir == "" {
		dir = filepath.Join("data", *nodeID)
	}

	// Stand-in for TPM/Secure-Enclave binding — see crypto/seal.go's doc
	// comment for what a real hardware integration replaces this with.
	root, err := mcrypto.LoadOrCreateRoot(dir, []byte("stand-in-hw-binding:"+*nodeID))
	if err != nil {
		log.Fatalf("impossibile caricare/creare la chiave radice: %v", err)
	}
	dbPath := filepath.Join(dir, "node.db")
	st, err := store.Open(dbPath, root)
	if err != nil {
		log.Fatalf("impossibile aprire lo store locale: %v", err)
	}
	defer st.Close()

	node := client.NewNode(*nodeID, endpoint, *orchestratorURL, st, root)
	node.SetLocalDBPath(dbPath)

	go func() {
		log.Printf("[%s] server P2P in ascolto su %s (raggiungibile come %s)", *nodeID, *peerAddr, endpoint)
		if err := http.ListenAndServe(*peerAddr, node.PeerMux()); err != nil {
			log.Fatalf("[%s] server P2P: %v", *nodeID, err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// give the peer server a moment to bind before registering/announcing
	time.Sleep(200 * time.Millisecond)
	if *meshOnly {
		log.Printf("[%s] modalità solo-mesh: nessuna registrazione presso un orchestratore, solo host di backup", *nodeID)
	} else if err := node.Start(ctx); err != nil {
		log.Fatalf("[%s] avvio fallito: %v", *nodeID, err)
	} else {
		go node.RunHeartbeats(ctx, 5*time.Second)
	}
	go node.Watchdog.Run(ctx, 2*time.Second)
	go node.SelfHeal(ctx, *healInterval, *healMargin)

	log.Printf("[%s] pronto. Digita 'help' per i comandi disponibili.", *nodeID)
	runREPL(node, ctx)
}

func runREPL(node *client.Node, ctx context.Context) {
	scanner := bufio.NewScanner(os.Stdin)
	printHelp()
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			// stdin closed (e.g. a scripted/piped command batch ended) —
			// the daemon's background services (peer server, heartbeats,
			// watchdog) keep running regardless of the REPL.
			log.Printf("stdin chiuso: il demone resta in esecuzione in background")
			<-ctx.Done()
			return
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "help":
			printHelp()

		case "store":
			if len(fields) != 5 {
				fmt.Println("uso: store <nome-segreto> <percorso-file> <soglia> <totale>")
				continue
			}
			data, err := os.ReadFile(fields[2])
			if err != nil {
				fmt.Println("errore lettura file:", err)
				continue
			}
			threshold, err1 := strconv.Atoi(fields[3])
			total, err2 := strconv.Atoi(fields[4])
			if err1 != nil || err2 != nil {
				fmt.Println("soglia e totale devono essere numeri interi")
				continue
			}
			if err := node.Split(fields[1], data, threshold, total); err != nil {
				fmt.Println("errore:", err)
				continue
			}
			fmt.Printf("ok: %q frammentato in %d quote (soglia %d) e distribuito ai pari\n", fields[1], total, threshold)

		case "reconstruct":
			if len(fields) != 3 {
				fmt.Println("uso: reconstruct <nome-segreto> <file-di-output>")
				continue
			}
			data, err := node.Reconstruct(fields[1])
			if err != nil {
				fmt.Println("errore:", err)
				continue
			}
			if err := os.WriteFile(fields[2], data, 0600); err != nil {
				fmt.Println("errore scrittura file:", err)
				continue
			}
			fmt.Printf("ok: %q ricostruito in %s (%d byte)\n", fields[1], fields[2], len(data))

		case "simulate-attack":
			node.Watchdog.SimulateAttack()
			fmt.Println("ok: reazione immunitaria innescata")

		case "status":
			printStatus(node)

		case "mesh-genkey":
			kp, err := mesh.GenerateKeyPair()
			if err != nil {
				fmt.Println("errore:", err)
				continue
			}
			fmt.Printf("chiave privata (tienila SOLO nel tuo wg-quick, non condividerla): %s\nchiave pubblica (da comunicare ai pari):                    %s\n", kp.PrivateKey, kp.PublicKey)

		case "mesh-add":
			if len(fields) != 4 {
				fmt.Println("uso: mesh-add <nome> <endpoint-http-su-tunnel-wg> <chiave-pubblica-wg>")
				continue
			}
			if err := node.AddMeshPeer(fields[1], fields[2], fields[3]); err != nil {
				fmt.Println("errore:", err)
				continue
			}
			fmt.Printf("ok: %q aggiunto alla mesh fidata (%s)\n", fields[1], fields[2])

		case "mesh-list":
			printMeshPeers(node)

		case "backup":
			if len(fields) != 4 {
				fmt.Println("uso: backup <etichetta> <percorso-file> <soglia>")
				continue
			}
			data, err := os.ReadFile(fields[2])
			if err != nil {
				fmt.Println("errore lettura file:", err)
				continue
			}
			threshold, err := strconv.Atoi(fields[3])
			if err != nil {
				fmt.Println("la soglia deve essere un numero intero")
				continue
			}
			if err := node.Backup(fields[1], data, threshold); err != nil {
				fmt.Println("errore:", err)
				continue
			}
			fmt.Printf("ok: backup %q distribuito sulla mesh fidata (soglia %d)\n", fields[1], threshold)

		case "backup-db":
			if len(fields) != 3 {
				fmt.Println("uso: backup-db <etichetta> <soglia>")
				continue
			}
			threshold, err := strconv.Atoi(fields[2])
			if err != nil {
				fmt.Println("la soglia deve essere un numero intero")
				continue
			}
			data, err := node.ReadOwnDatabaseFile()
			if err != nil {
				fmt.Println("errore lettura database locale:", err)
				continue
			}
			if err := node.Backup(fields[1], data, threshold); err != nil {
				fmt.Println("errore:", err)
				continue
			}
			fmt.Printf("ok: database locale salvato come backup %q sulla mesh fidata (soglia %d)\n", fields[1], threshold)

		case "heal-now":
			node.HealNow()
			fmt.Println("ok: ciclo di auto-guarigione eseguito (vedi il log per l'esito)")

		case "quit", "exit":
			return

		default:
			fmt.Println("comando sconosciuto — digita 'help'")
		}
	}
}

func printHelp() {
	fmt.Println(`comandi disponibili:
  store <nome-segreto> <percorso-file> <soglia> <totale>     frammenta e distribuisce un file (protocollo di mutazione, via orchestratore)
  reconstruct <nome-segreto> <file-di-output>                 ricostruisce un segreto o un backup precedentemente distribuito
  simulate-attack                                             forza la reazione immunitaria completa (demo)
  status                                                       mostra le quote detenute localmente

  mesh-genkey                                                 genera una coppia di chiavi WireGuard per questo dispositivo
  mesh-add <nome> <endpoint> <chiave-pubblica-wg>              aggiunge un pari alla mesh fidata (backup off-site)
  mesh-list                                                    elenca i pari della mesh fidata
  backup <etichetta> <percorso-file> <soglia>                  frammenta e distribuisce un backup sulla mesh fidata (nessun orchestratore coinvolto)
  backup-db <etichetta> <soglia>                               salva il database locale stesso come backup sulla mesh fidata
  heal-now                                                     forza subito un ciclo di auto-guarigione (backup E segreti posseduti)

  quit                                                         esce`)
}

func printMeshPeers(node *client.Node) {
	peers, err := node.ListMeshPeers()
	if err != nil {
		fmt.Println("errore:", err)
		return
	}
	if len(peers) == 0 {
		fmt.Println("nessun pari nella mesh fidata")
		return
	}
	for _, p := range peers {
		fmt.Printf("  %s  %s  wg-pubkey=%s\n", p.Name, p.Endpoint, p.WGPublicKey)
	}
}

func printStatus(node *client.Node) {
	pids, err := node.ListLocalFragments()
	if err != nil {
		fmt.Println("errore:", err)
		return
	}
	if len(pids) == 0 {
		fmt.Println("nessuna quota detenuta localmente")
		return
	}
	fmt.Printf("punteggio watchdog corrente: %d\n", node.Watchdog.Score())
	for _, f := range pids {
		fmt.Printf("  pid=%s  gruppo=%s  epoch=%d  soglia=%d/%d\n", f.PID, f.GroupID, f.Epoch, f.Threshold, f.Total)
	}
}
