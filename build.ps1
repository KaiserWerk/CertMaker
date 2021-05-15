$sourcecode = "cmd/certmaker/main.go"
$target = "build/certmaker"
# Windows, 64-bit
$env:GOOS = 'windows'; $env:GOARCH = 'amd64';             go build -o "$($target)-win64.exe" -ldflags "-s -w" $sourcecode
# Linux, 64-bit
$env:GOOS = 'linux';   $env:GOARCH = 'amd64';             go build -o "$($target)-linux64"   -ldflags "-s -w" $sourcecode
# Raspberry Pi
$env:GOOS = 'linux';   $env:GOARCH = 'arm'; $env:GOARM=5; go build -o "$($target)-raspi32"   -ldflags "-s -w" $sourcecode
# macOS
$env:GOOS = 'darwin';  $env:GOARCH = 'amd64';             go build -o "$($target)-macos64"   -ldflags "-s -w" $sourcecode
