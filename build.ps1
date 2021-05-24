$sourcecode = "cmd/certmaker/main.go"
$target = "build/certmaker"
# Windows, 64-bit
$env:GOOS = 'windows'; $env:GOARCH = 'amd64';             go build -o "$($target)-windows-amd64.exe" -ldflags "-s -w" $sourcecode
# Linux, 64-bit
$env:GOOS = 'linux';   $env:GOARCH = 'amd64';             go build -o "$($target)-linux-amd64"   -ldflags "-s -w" $sourcecode
# Raspberry Pi
$env:GOOS = 'linux';   $env:GOARCH = 'arm'; $env:GOARM=5; go build -o "$($target)-raspberrypi-arm5"   -ldflags "-s -w" $sourcecode
# macOS
$env:GOOS = 'darwin';  $env:GOARCH = 'amd64';             go build -o "$($target)-macos-amd64"   -ldflags "-s -w" $sourcecode
