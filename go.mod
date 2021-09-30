module benkyo.dev/network_monitoring

go 1.17

require (
	benkyo.dev/dnsTool v0.0.0-00010101000000-000000000000
	github.com/osquery/osquery-go v0.0.0-20210622151333-99b4efa62ec5
)

replace benkyo.dev/dnsTool => ./pcap
