package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"

	pcap "benkyo.dev/dnsTool"
)

var (
	osqueryExtenstionSocket string = "/root/.osquery/shell.em"
	serviceName             string = "benkyo-dns-watching"
	tableName               string = "benkyo"
	configPath              string = "/var/osquery/extensions/v2-security/conf.json"
)

type configFile struct {
	Network_interface string `json:"network-interface"`
}

func main() {

	var config configFile
	err := loadConfiguration(&config)
	if err != nil {
		log.Fatalf("Could not load configuration file, %v\n", err)
	}

	defer pcap.Close()
	pcap.Start(config.Network_interface)

	server, err := osquery.NewExtensionManagerServer(serviceName, osqueryExtenstionSocket)
	defer server.Shutdown(context.Background())

	if err != nil {
		log.Fatalf("Error in creating extension: %v\n", err)
	}
	log.Println("Connect socket successfully")

	if err != nil {
		log.Fatalf("Error in setup DNS filter: %v\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin(tableName, DnsTableColumns(), DnsRecording))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

func loadConfiguration(config *configFile) error {
	bs, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bs, config)
	if err != nil {
		return err
	}
	if len(config.Network_interface) <= 0 {
		return errors.New("invalid network interface")
	}
	return nil
}

// DnsTableColumns returns the columns that our table will return.
func DnsTableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Time"),
		table.TextColumn("Name"),
		table.TextColumn("Type"),
		table.TextColumn("IP_CNAME"),
		table.TextColumn("Protocol"),
	}
}

// DnsRecording will be called whenever the table is queried. It should return
// a full table scan.
func DnsRecording(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return pcap.GetData(), nil
}
