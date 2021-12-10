// Target filled by GitHub Actions, one for the regular tag, one for the debug tag
target "docker-metadata-action" {}
target "docker-metadata-action-debug" {}

target "default" {
  dockerfile = "Dockerfile"
  context = "./"
}

target "debug" {
  inherits = ["default"]
  target = "debug"
}

target "release" {
  inherits = ["default"]
  platforms = [
    "linux/amd64",
    "linux/arm64",
    "linux/arm",
  ]
}

// This is what is baked by GitHub Actions
group "gha" { targets = ["gha-regular", "gha-debug"] }

target "gha-base" {
  inherits = ["release"]
  cache-from = ["type=gha"]
  cache-to = ["type=gha,mode=max"]
}

target "gha-regular" {
  inherits = ["gha-base", "docker-metadata-action"]
}

target "gha-debug" {
  inherits = ["gha-base", "debug", "docker-metadata-action-debug"]
}
