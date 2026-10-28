$version = git describe --tags --abbrev=0
if ($LASTEXITCODE -ne 0) {
    throw "Git-Tag konnte nicht ermittelt werden."
}

$version = $version.Trim()
if (-not $version) {
    throw "Git hat einen leeren Tag zurückgegeben."
}

docker build --build-arg "VERSION=$version" -t "meinprogramm:$version" .
if ($LASTEXITCODE -ne 0) {
    throw "Docker-Build fehlgeschlagen."
}