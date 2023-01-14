package tools

import (
	"fmt"
	"time"
)

func ExeTime(name string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s execution time: %v\n", name, time.Since(start))
	}
}
