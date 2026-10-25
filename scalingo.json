{
  "$schema": "https://developers.scalingo.com/scalingo-json-schema/index",
  "name": "Bermuda Portal",
  "description": "High-performance L7 edge router and automated configuration synthesis engine for Scalingo PaaS and Cloudflare Edge.",
  "stack": "scalingo-24",
  "env": {
    "GOVERSION": {
      "description": "Pinned Go compiler series for Scalingo go-buildpack",
      "value": "go1.27"
    },
    "CGO_ENABLED": {
      "description": "Build static Go binary without C dependencies",
      "value": "0"
    },
    "GOFLAGS": {
      "description": "Compiler flags for stripped production binary",
      "value": "-trimpath -ldflags=-s -w"
    },
    "TZ": {
      "description": "Container timezone",
      "value": "UTC"
    },
    "GOGC": {
      "description": "Go garbage collector target percentage",
      "value": "100"
    },
    "GODEBUG": {
      "description": "Return unused memory pages to the OS kernel immediately",
      "value": "madvdontneed=1"
    },
    "BERMUDA_REGION": {
      "description": "Scalingo deployment region identifier (osc-fr1 or osc-secnum-fr1)",
      "value": "osc-fr1"
    },
    "BERMUDA_MASTER_KEY": {
      "description": "Master cryptographic seed for deterministic KDF credential synthesis",
      "generator": "secret"
    },
    "PUBLIC_ORIGIN_URL": {
      "description": "Dynamic Scalingo application origin URL",
      "generator": "template",
      "template": "https://%APP%.osc-fr1.scalingo.io"
    },
    "CLOUDFLARE_API_TOKEN": {
      "description": "Optional Cloudflare API Token for automated DNS and Edge Ruleset tuning",
      "value": "",
      "required": false
    },
    "SCALINGO_API_TOKEN": {
      "description": "Optional Scalingo Personal API Token (tk-us-...) for zero-touch domain and variable provisioning",
      "value": "",
      "required": false
    },
    "CUSTOM_DOMAIN": {
      "description": "Optional custom domain routed via Cloudflare Edge",
      "value": "",
      "required": false
    }
  },
  "formation": {
    "web": {
      "amount": 1,
      "size": "M"
    }
  }
}
