// util.go — progres dan jeda CLI.
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"bufio"
	"fmt"
	"os"
)

func printProgress(processed, total int64) {
	if total <= 0 {
		fmt.Printf("\r  ... %.2f MB diproses", float64(processed)/1024/1024)
		return
	}
	pct := float64(processed) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	fmt.Printf("\r  ... %5.1f%% (%.1f/%.1f MB)", pct, float64(processed)/1024/1024, float64(total)/1024/1024)
}

// pause agar .exe yang di-double-click tidak langsung tertutup.
func pause() {
	fmt.Print("Tekan Enter untuk keluar... ")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
