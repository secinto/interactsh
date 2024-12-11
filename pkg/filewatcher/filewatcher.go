package filewatcher

import (
	"bufio"
	"errors"
	"github.com/secinto/interactsh/pkg/logging"
	"os"
	"sync"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	log = logging.NewLogger()
)

type Options struct {
	Interval time.Duration
	File     string
}

type FileWatcher struct {
	Options Options
	watcher *time.Ticker
}

func New(options Options) (*FileWatcher, error) {
	return &FileWatcher{Options: options}, nil
}

func (f *FileWatcher) Watch() (chan string, error) {
	tickWatcher := time.NewTicker(f.Options.Interval)
	f.watcher = tickWatcher
	out := make(chan string)
	if !fileutil.FileExists(f.Options.File) {
		return nil, errors.New("file doesn't exist")
	}
	go func() {
		var seenLines sync.Map
		for range f.watcher.C {
			r, err := os.Open(f.Options.File)
			if err != nil {
				log.Fatalf("Couldn't monitor file: %s", err)
				return
			}
			sc := bufio.NewScanner(r)
			for sc.Scan() {
				data := sc.Text()
				_, loaded := seenLines.LoadOrStore(data, struct{}{})
				if !loaded {
					out <- data
				}

			}
			r.Close()
		}
	}()
	return out, nil
}

func (f *FileWatcher) Close() {
	f.watcher.Stop()
}
