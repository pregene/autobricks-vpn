# Ubuntu server DEB

Build both Ubuntu 22.04 packages from the repository root:

```sh
python3 scripts/build-deb.py
```

The Docker build uses Ubuntu 22.04 for both `amd64` and `arm64`. Generated
packages are written to `build/`. Docker builder images are cached locally so
subsequent builds do not rebuild wolfSSL unless the build definition changes.
Each DEB is accompanied by a `.sha256` file containing its SHA-256 checksum.

Install the package interactively:

```sh
sha256sum -c autobricks-vpn-server-0.8.107-ubunbtu-22.04-ARCH.deb.sha256
sudo dpkg -i autobricks-vpn-server-0.8.107-ubunbtu-22.04-ARCH.deb
```

The first installation asks for the certificate subject, public IPv4 address,
VPN network, VPN server address, and service port. It creates the Root CA,
Intermediate CA, server certificate, and `/etc/autobricks-vpn/server.ini`.
Existing configuration, certificates, registered clients, and web data are
preserved during package upgrades.

The VPN service does not depend on Node.js. The management web requires
Node.js 18 or later. Node.js 22 LTS is recommended on Ubuntu 22.04. Install or
upgrade it from the NodeSource repository:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
```

If Node.js is missing or too old, only the web service stops after five
immediate failures. After installing or updating Node.js, run:

```sh
sudo systemctl reset-failed autobricks-vpn-web.service
sudo systemctl restart autobricks-vpn-web.service
```

Remove program files and preserve configuration, PKI, registered clients, and
web data:

```sh
sudo dpkg --remove autobricks-vpn-server
```

Permanently remove all configuration, certificates, the Root CA private key,
registered clients, and web data:

```sh
sudo dpkg --purge autobricks-vpn-server
```

Back up `/etc/autobricks-vpn/root-private/root-ca-key.pem` before purging.
