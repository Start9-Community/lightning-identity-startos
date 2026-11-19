package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lundog/lightning-identity-startos/service/internal/site"
)

// siteCommand is `edge site install|remove`: the one-off that the Upload
// Site and Remove Site actions run in a throwaway container. It is in this
// binary because edge is the process with nothing to protect: it links no
// credential code and the container it runs in mounts only the upload and
// site folders. It prints a JSON report on stdout, or one sentence saying
// what was wrong on stderr and exits 1.
func siteCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: edge site install|remove ...")
		return 2
	}
	fl := flag.NewFlagSet("edge site "+args[0], flag.ContinueOnError)
	dest := fl.String("dest", "/site", "the site folder")
	switch args[0] {
	case "install":
		archive := fl.String("archive", "", "the uploaded zip")
		keep := fl.Bool("keep", false, "keep the files already in the site folder")
		maxArchive := fl.Int64("max-archive", site.DefaultMaxArchive, "largest archive accepted, in bytes")
		maxBytes := fl.Int64("max-bytes", site.DefaultMaxBytes, "largest unpacked size accepted, in bytes")
		maxFiles := fl.Int("max-files", site.DefaultMaxFiles, "most files accepted")
		if err := fl.Parse(args[1:]); err != nil {
			return 2
		}
		rep, err := site.Install(*archive, *dest, site.Options{Keep: *keep, MaxArchive: *maxArchive, MaxBytes: *maxBytes, MaxFiles: *maxFiles})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		return 0
	case "remove":
		if err := fl.Parse(args[1:]); err != nil {
			return 2
		}
		removed, err := site.Remove(*dest)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]int{"removed": removed})
		return 0
	}
	fmt.Fprintf(os.Stderr, "edge site: unknown command %q\n", args[0])
	return 2
}
