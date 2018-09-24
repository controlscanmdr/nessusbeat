package beater

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/OnBeep/backoff"
	"github.com/attwad/nessie"
	"github.com/fsnotify/fsnotify"

	"github.com/dunbarcyber/nessusbeat/config"
	"sync"
)

type Nessusbeat struct {
	done   chan struct{}   // Channel that closes when the beat was signaled to close.
	config config.Config   // Parsed configuration file options.
	scans  map[string]bool // Map of the current ongoing scans.
	name   string          // Configured beat name retrieved from b.Info.Name.
	mutex  sync.Mutex      // Locking mutex to prevent concurrent writes to scans map.
	events chan beat.Event // Channel containing the parsed nessus scan events.
	client beat.Client     //
}

func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	conf := config.DefaultConfig
	if err := cfg.Unpack(&conf); err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	return &Nessusbeat{config: conf}, nil
}

// Connects to the nessus REST API.
func connectAPI(url, cert string) (nessie.Nessus, error) {
	switch cert {
	case "":
		return nessie.NewInsecureNessus(url)
	default:
		return nessie.NewNessus(url, cert)
	}
}

// Retrieves the scan ID by it's UUID.
func scanID(nessus nessie.Nessus, uuid string) (int64, error) {
	result, err := nessus.Scans()
	if err != nil {
		return 0, err
	}
	for _, scan := range result.Scans {
		if scan.UUID == uuid {
			return scan.ID, nil
		}
	}
	return 0, nil
}

// Creates a watcher to watch a specified path.
func watch(path string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("cannot create watcher: %s", err)
	}
	err = watcher.Add(path)
	if err != nil {
		return nil, fmt.Errorf("cannot watch path '%s': %s", path, err)
	}
	return watcher, nil
}

// Downloads a nessus scan matching the given UUID.
func exportCSVScan(nessus nessie.Nessus, uuid string) ([]byte, error) {
	scanID, err := scanID(nessus, uuid)
	if err != nil {
		return nil, err
	}
	exportID, err := nessus.ExportScan(scanID, nessie.ExportCSV)
	if err != nil {
		return nil, err
	}
	// Wait for the scan to be finished before exporting.
	for {
		finished, err := nessus.ExportFinished(scanID, exportID)
		if err != nil {
			return nil, err
		}
		if finished {
			break
		}
		time.Sleep(5 * time.Second)
	}
	return nessus.DownloadExport(scanID, exportID)
}

// Adds a UUID to current processing scan list to prevent multiple scans of the same UUID from occurring.
func (bt *Nessusbeat) trackUUID(uuid string) bool {
	bt.mutex.Lock()
	if bt.scans[uuid] {
		return false
	}
	bt.scans[uuid] = true
	bt.mutex.Unlock()
	return true
}

// Removes a UUID from the currently processing scans.
func (bt *Nessusbeat) forgetUUID(uuid string) {
	bt.mutex.Lock()
	delete(bt.scans, uuid)
	bt.mutex.Unlock()
}

// Scans the file at the specified path and emits events based on the nessus scan contents.
func (bt *Nessusbeat) scan(path string) {
	// Retrieve UUID from nessus file.
	basename := filepath.Base(path)
	uuid := strings.TrimSuffix(basename, filepath.Ext(basename))

	// If UUID is already being scanned, ignore this call.
	if !bt.trackUUID(uuid) {
		return
	}
	defer bt.forgetUUID(uuid) // Remove UUID after scan is complete.
	logp.Info("exporting nessus scan '%s'", uuid)
	var b []byte

	// Try to connect to the nessus API to retrieve the newest scan.
	err := backoff.RetryNotify(
		func() error {
			nessus, err := connectAPI(bt.config.APIUrl, bt.config.CACertPath)
			if err != nil {
				return fmt.Errorf("cannot connect to nessus API: %s", err)
			}
			if err = nessus.Login(bt.config.APIUsername, bt.config.APIPassword); err != nil {
				return fmt.Errorf("cannot login to nessus API: %s", err)
			}
			defer nessus.Logout()
			b, err = exportCSVScan(nessus, uuid)
			if err != nil {
				return fmt.Errorf("cannot retrieve nessus scan '%s': %s", uuid, err)
			}
			return nil
		},
		backoff.WithMaxTries(backoff.NewExponentialBackOff(), 5),
		func(err error, duration time.Duration) {
			logp.Warn(err.Error())
			logp.Warn("retrying connection in %s", duration)
		},
	)
	if err != nil {
		logp.Err(err.Error())
		return
	}
	bt.readCSVScan(b)
}

// Places an even onto the events channel. This should typically be called with go to prevent the
// goroutine from blocking.
func (bt *Nessusbeat) emit(event beat.Event) { bt.events <- event }

// Begins watching for nessus file write events from the given watcher.
func (bt *Nessusbeat) watch(watcher *fsnotify.Watcher) error {
	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write && filepath.Ext(event.Name) == ".nessus" {
				// Start scan in goroutine in order to consume back to back fsnotify write events.
				// Otherwise the events will queue until the scan is done, which will create a cascade of
				// duplicate events.
				go bt.scan(event.Name)
			}
		case err := <-watcher.Errors:
			logp.Err(err.Error())
		}
	}
}

// Read a nessus scan and emit each record as an event.
func (bt *Nessusbeat) readCSVScan(result []byte) {
	r := csv.NewReader(bytes.NewReader(result))
	_, err := r.Read() // skip header row
	if err != nil {
		logp.Err(err.Error())
		return
	}
	for {
		record, err := r.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			logp.Err(err.Error())
			return
		}
		if len(record) != 13 {
			logp.Err("invalid field count: expected '13' fields but received '%d", len(record))
			continue
		}
		now := time.Now()
		event := beat.Event{
			Timestamp: now,
			Fields: common.MapStr{
				"@timestamp":    common.Time(now),
				"type":          bt.name,
				"plugin_id":     record[0],
				"cve":           record[1],
				"cvss":          record[2],
				"risk":          record[3],
				"host":          record[4],
				"protocol":      record[5],
				"port":          record[6],
				"name":          record[7],
				"synopsis":      record[8],
				"description":   record[9],
				"solution":      record[10],
				"see_also":      record[11],
				"plugin_output": record[12],
			},
		}

		// Place current timestamp on any other configured timestamp fields.
		for _, field := range strings.Split(bt.config.TimestampFields, ",") {
			event.Fields[strings.TrimSpace(field)] = now
		}

		go bt.emit(event) // Emit the event asynchronously to prevent holding up the event channel.
	}
}

// Starts the nessus beat.
func (bt *Nessusbeat) Run(b *beat.Beat) error {
	logp.Info("nessusbeat is running! Hit CTRL-C to stop it.")

	// Create watcher with the given report path.
	watcher, err := watch(bt.config.ReportPath)
	if err != nil {
		logp.WTF(err.Error())
	}
	bt.client, err = b.Publisher.Connect()

	// Initialize channels in run step instead of initialization, otherwise if a beat is stopped
	// then restarted it will
	bt.done = make(chan struct{})
	bt.events = make(chan beat.Event)

	go bt.watch(watcher)

	for {
		select {
		case <-bt.done:
			return nil
		case event := <-bt.events:
			bt.client.Publish(event)
		}
	}
}

// Stops the nessus beat.
func (bt *Nessusbeat) Stop() {
	bt.client.Close()
	close(bt.done)
	close(bt.events)
}
