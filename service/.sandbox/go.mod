module github.com/lundog/lightning-identity-startos/service

go 1.24.1

toolchain go1.24.7

require (
	github.com/fiatjaf/eventstore v0.16.2
	github.com/fiatjaf/khatru v0.19.1
	github.com/nbd-wtf/go-nostr v0.52.3
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.47.0
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/macaroon.v2 v2.1.0
)

require (
	github.com/ImVexed/fasturl v0.0.0-20230304231329-4e41488060f3 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/bep/debounce v1.2.1 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/coder/websocket v1.8.13 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/fasthttp/websocket v1.5.12 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/savsgio/gotils v0.0.0-20240704082632-aef3928b8a38 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.59.0 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
)

replace go.etcd.io/bbolt => github.com/etcd-io/bbolt v1.4.3

replace gopkg.in/macaroon.v2 => ./.sandbox/third_party/macaroon

replace golang.org/x/crypto => github.com/golang/crypto v0.36.0

replace golang.org/x/net => github.com/golang/net v0.49.0

replace golang.org/x/sys => github.com/golang/sys v0.40.0

replace golang.org/x/text => github.com/golang/text v0.33.0

replace golang.org/x/sync => github.com/golang/sync v0.19.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20250305212735-054e65f0b394

replace google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.36.12

replace golang.org/x/term => ./.sandbox/stubs/golang_org_x_term

replace golang.org/x/tools => ./.sandbox/stubs/golang_org_x_tools

replace golang.org/x/mod => ./.sandbox/stubs/golang_org_x_mod

replace gopkg.in/yaml.v3 => ./.sandbox/stubs/gopkg_in_yaml_v3

replace golang.org/x/xerrors => ./.sandbox/stubs/golang_org_x_xerrors

replace gopkg.in/yaml.v2 => ./.sandbox/stubs/gopkg_in_yaml_v2

replace gopkg.in/tomb.v1 => ./.sandbox/stubs/gopkg_in_tomb_v1

replace gopkg.in/fsnotify.v1 => ./.sandbox/stubs/gopkg_in_fsnotify_v1

replace google.golang.org/grpc => github.com/grpc/grpc-go v1.80.0

replace google.golang.org/genproto/googleapis/rpc => github.com/googleapis/go-genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516
