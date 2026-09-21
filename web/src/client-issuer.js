import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createPrivateKey, generateKeyPairSync, randomBytes, X509Certificate } from "node:crypto";
import { validateClientAddress } from "./server-config.js";

function bad(message, status = 400, code = "invalid_request") {
  return Object.assign(new Error(message), { status, code });
}

function runOpenSsl(args) {
  try {
    execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"], timeout: 10000 });
  } catch (error) {
    throw bad(`인증서 발급 실패: ${error.stderr?.toString().trim() || error.message}`, 503, "certificate_issuance_failed");
  }
}

function pemSection(name, pem) {
  return `[${name}]\n${pem.trim()}\n`;
}

export class ClientIssuer {
  constructor(settings, configPath) {
    this.settings = settings;
    this.configPath = configPath;
    this.baseDirectory = path.resolve(path.dirname(configPath), "..");
  }

  file(value) {
    if (!value) throw bad("server.ini에 CA 및 서버 인증서 경로를 설정해야 합니다.", 503, "signer_not_configured");
    return path.resolve(this.baseDirectory, value);
  }

  pem(section, fallback) {
    const text = fs.readFileSync(this.configPath, "utf8");
    const lines = text.split(/\r?\n/);
    const start = lines.findIndex((line) => line.trim() === `[${section}]`);
    if (start < 0) return fs.readFileSync(this.file(fallback), "utf8");
    const end = lines.findIndex((line, index) => index > start && /^\s*\[[^\]]+\]\s*$/.test(line));
    const pem = lines.slice(start + 1, end < 0 ? undefined : end).join("\n").trim();
    if (!pem.includes("-----BEGIN ") || !pem.includes("-----END ")) throw bad(`server.ini의 [${section}] PEM이 올바르지 않습니다.`, 503, "invalid_embedded_pem");
    return `${pem}\n`;
  }

  issue(input = {}) {
    const { settings } = this;
    const name = String(input.name ?? "").trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(name)) throw bad("클라이언트 이름은 영문, 숫자, 점, 밑줄, 하이픈으로 입력하세요.");
    const vpnAddress = validateClientAddress(input.vpnAddress, settings);
    const validityDays = Number(input.validityDays ?? 365);
    if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 825) throw bad("유효 기간은 1~825일이어야 합니다.");

    const rootPem = this.pem("root_ca", settings.rootCaFile);
    const intermediatePem = this.pem("intermediate_ca", settings.intermediateCaFile);
    const intermediateKeyPem = this.pem("intermediate_key", settings.intermediateCaKeyFile);
    const serverCertificate = new X509Certificate(this.pem("certificate", settings.certificateFile));
    const issuer = new X509Certificate(intermediatePem);
    const root = new X509Certificate(rootPem);
    if (!issuer.checkIssued(root) || !issuer.verify(root.publicKey)) {
      throw bad("Intermediate CA와 Root CA 체인이 일치하지 않습니다.", 503, "invalid_ca_chain");
    }
    if (!issuer.ca || !root.ca || !issuer.checkPrivateKey(createPrivateKey(intermediateKeyPem))) {
      throw bad("Intermediate CA 개인키가 인증서와 일치하지 않습니다.", 503, "invalid_ca_key");
    }
    if (!serverCertificate.checkIssued(issuer) || !serverCertificate.verify(issuer.publicKey)) {
      throw bad("서버 인증서가 설정된 Intermediate CA에서 발급되지 않았습니다.", 503, "invalid_server_certificate");
    }
    const sanIp = serverCertificate.subjectAltName?.match(/IP Address:([0-9.]+)/)?.[1];
    const serverAddress = settings.publicAddress || sanIp;
    if (!serverAddress || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(serverAddress) ||
        (settings.issuedClientVerifyServerSanIp && sanIp && serverAddress !== sanIp)) {
      throw bad("서버 공개 주소가 인증서 SAN IP와 일치해야 합니다.", 503, "invalid_server_address");
    }

    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-issue-"));
    try {
      fs.chmodSync(temporary, 0o700);
      const keyPath = path.join(temporary, "client-key.pem");
      const csrPath = path.join(temporary, "client.csr");
      const certPath = path.join(temporary, "client-cert.pem");
      const extPath = path.join(temporary, "client.ext");
      const intermediateCertPath = path.join(temporary, "intermediate-ca.pem");
      const intermediateKeyPath = path.join(temporary, "intermediate-key.pem");
      fs.writeFileSync(intermediateCertPath, intermediatePem, { mode: 0o600 });
      fs.writeFileSync(intermediateKeyPath, intermediateKeyPem, { mode: 0o600 });
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
      fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
      fs.writeFileSync(extPath, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=IP:${vpnAddress}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`);
      runOpenSsl(["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", `/CN=${name}`]);
      runOpenSsl(["x509", "-req", "-in", csrPath, "-CA", intermediateCertPath, "-CAkey", intermediateKeyPath, "-set_serial", `0x${randomBytes(16).toString("hex")}`, "-days", String(validityDays), "-sha256", "-extfile", extPath, "-out", certPath]);
      const certificatePem = fs.readFileSync(certPath, "utf8");
      const certificate = new X509Certificate(certificatePem);
      if (!certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey)) throw bad("발급된 인증서를 검증할 수 없습니다.", 503, "certificate_issuance_failed");
      const fingerprint = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
      const config = `[client]\nserver_address = ${serverAddress}\nverify_server_san_ip = true\nport = ${settings.port}\nkeepalive_interval = 30\ninput_process_batch = 64\ncertificate_file = embedded\nprivate_key_file = embedded\nca_file = embedded\nocsp_enabled = false\ntun_name = autobricks1\nvpn_address = ${vpnAddress}\nvpn_gateway = ${settings.vpnAddress}\nvpn_network = ${settings.vpnNetwork}\ndns_server = ${settings.vpnAddress}\nforce_dns = false\nmtu = ${settings.mtu}\n\n${pemSection("certificate", certificatePem)}\n${pemSection("key", privateKey)}\n${pemSection("ca", `${intermediatePem.trim()}\n${rootPem.trim()}`)}`;
      const clientConfig = config.replace(
        "verify_server_san_ip = true",
        `verify_server_san_ip = ${settings.issuedClientVerifyServerSanIp}`,
      );
      return { vpnAddress, fingerprint, filename: `${name}-client.ini`, content: clientConfig };
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  }
}
