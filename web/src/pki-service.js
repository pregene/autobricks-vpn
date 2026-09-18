import { X509Certificate, randomUUID } from "node:crypto";

export class PkiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function requiredText(value, field, maximum = 4096) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new PkiError(400, "invalid_request", `${field} is required.`);
  }
  if (value.length > maximum) {
    throw new PkiError(400, "invalid_request", `${field} is too long.`);
  }
  return value.trim();
}

function normalizeFingerprint(value) {
  return value.replaceAll(":", "").toLowerCase();
}

function validateVpnAddress(value) {
  const address = requiredText(value, "vpnAddress", 15);
  const match = /^10\.8\.1\.(\d{1,3})$/.exec(address);
  const host = match ? Number(match[1]) : -1;
  if (host < 2 || host > 254) {
    throw new PkiError(400, "invalid_vpn_address", "vpnAddress must be a client address in 10.8.1.2-10.8.1.254.");
  }
  return address;
}

export class PkiService {
  #certificates = [];
  #requests = [];

  capabilities() {
    return {
      serverCertificateRegistration: true,
      clientCertificateIssuance: false,
      revocation: false,
      signer: "not_configured",
      message: "외부 CA 서명 서비스를 연결하면 발급과 폐기가 활성화됩니다.",
    };
  }

  list() {
    return {
      certificates: [...this.#certificates],
      requests: [...this.#requests],
    };
  }

  registerServerCertificate(input = {}) {
    const certificatePem = requiredText(input.certificatePem, "certificatePem", 32768);
    const keyReference = requiredText(input.keyReference, "keyReference", 1024);
    if (!keyReference.startsWith("/")) {
      throw new PkiError(400, "invalid_key_reference", "keyReference must be an absolute server-side path.");
    }

    let certificate;
    try {
      certificate = new X509Certificate(certificatePem);
    } catch {
      throw new PkiError(400, "invalid_certificate", "certificatePem is not a valid X.509 PEM certificate.");
    }

    const fingerprint = normalizeFingerprint(certificate.fingerprint256);
    if (this.#certificates.some((item) => item.fingerprint === fingerprint)) {
      throw new PkiError(409, "certificate_exists", "This certificate is already registered.");
    }

    const item = {
      id: randomUUID(),
      type: "server",
      subject: certificate.subject,
      subjectAltName: certificate.subjectAltName ?? "",
      fingerprint,
      validFrom: new Date(certificate.validFrom).toISOString(),
      validTo: new Date(certificate.validTo).toISOString(),
      keyReference,
      status: "registered",
      registeredAt: new Date().toISOString(),
    };
    this.#certificates.unshift(item);
    return item;
  }

  requestClientCertificate(input = {}) {
    const name = requiredText(input.name, "name", 128);
    const vpnAddress = validateVpnAddress(input.vpnAddress);
    const csrPem = requiredText(input.csrPem, "csrPem", 32768);
    const validityDays = Number(input.validityDays);

    if (!csrPem.includes("-----BEGIN CERTIFICATE REQUEST-----") ||
        !csrPem.includes("-----END CERTIFICATE REQUEST-----")) {
      throw new PkiError(400, "invalid_csr", "csrPem must be a PEM certificate signing request.");
    }
    if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 825) {
      throw new PkiError(400, "invalid_validity", "validityDays must be an integer from 1 to 825.");
    }
    if (this.#requests.some((item) => item.vpnAddress === vpnAddress && item.status === "awaiting_signer")) {
      throw new PkiError(409, "vpn_address_pending", "This VPN address already has a pending request.");
    }

    const request = {
      id: randomUUID(),
      type: "client",
      name,
      vpnAddress,
      validityDays,
      status: "awaiting_signer",
      requestedAt: new Date().toISOString(),
    };
    this.#requests.unshift(request);
    return request;
  }
}
