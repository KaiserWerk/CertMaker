$sourcecode = "cmd/certmaker/main.go"
$target = "build/certmaker"
$version = "v2.0.2"
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
# Windows, 64-bit
$env:GOOS = 'windows'; $env:GOARCH = 'amd64';             go build -o "$($target)-windows-amd64-$($version).exe"  -ldflags "-s -w -X 'main.Version=$($version)' -X 'main.VersionDate=$($date)'" $sourcecode
# Linux, 64-bit
$env:GOOS = 'linux';   $env:GOARCH = 'amd64';             go build -o "$($target)-linux-amd64-$($version)"        -ldflags "-s -w -X 'main.Version=$($version)' -X 'main.VersionDate=$($date)'" $sourcecode
# Raspberry Pi
$env:GOOS = 'linux';   $env:GOARCH = 'arm'; $env:GOARM=5; go build -o "$($target)-raspberrypi-arm5-$($version)"   -ldflags "-s -w -X 'main.Version=$($version)' -X 'main.VersionDate=$($date)'" $sourcecode
# macOS
$env:GOOS = 'darwin';  $env:GOARCH = 'amd64';             go build -o "$($target)-macos-amd64-$($version)"        -ldflags "-s -w -X 'main.Version=$($version)' -X 'main.VersionDate=$($date)'" $sourcecode
