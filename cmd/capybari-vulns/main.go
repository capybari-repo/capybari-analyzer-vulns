// Command capybari-vulns runs this capability on its own. It needs the
// dependency inventory, so it bundles capybari-analyzer-dependencies.
package main

import (
	dependencies "github.com/capybari-repo/capybari-analyzer-dependencies"
	vulns "github.com/capybari-repo/capybari-analyzer-vulns"
	"github.com/capybari-repo/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, vulns.New(), dependencies.New()) }
