module github.com/yourorg/stac-proxy

go 1.25.0

require (
	// Web framework
	github.com/go-chi/chi/v5 v5.1.0

	// Authentication
	github.com/golang-jwt/jwt/v5 v5.2.1

	// Authorization - OPA
	github.com/open-policy-agent/opa v0.70.0

	// Observability
	github.com/prometheus/client_golang v1.20.5

	// Utilities
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.25.0
	gopkg.in/yaml.v3 v3.0.1
)

// pinned: no upstream tag yet — bump deliberately and re-run helper tests
require github.com/exergy-dev/go-cql2 v0.0.0-20260504204024-796456d5f243

require (
	github.com/exergy-dev/go-topology-suite v0.1.0
	github.com/google/uuid v1.6.0
	golang.org/x/sync v0.10.0
)

require (
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/agnivade/levenshtein v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
