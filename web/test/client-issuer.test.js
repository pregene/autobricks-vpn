import assert from "node:assert/strict";
import test from "node:test";
import { clientCertificateExtensions, validateAllowedSourceCidr } from "../src/client-issuer.js";

test("validates an optional canonical allowed source CIDR", () => {
  assert.equal(validateAllowedSourceCidr(""), null);
  assert.equal(validateAllowedSourceCidr("192.0.2.0/24"), "192.0.2.0/24");
  assert.equal(validateAllowedSourceCidr("192.0.2.10/32"), "192.0.2.10/32");
  assert.throws(() => validateAllowedSourceCidr("192.0.2.10/24"), /host bit/);
  assert.throws(() => validateAllowedSourceCidr("300.0.0.0/24"), /IPv4 CIDR/);
  assert.throws(() => validateAllowedSourceCidr("192.0.2.0/33"), /IPv4 CIDR/);
});

test("adds the allowed source policy only to the client certificate URI SAN", () => {
  const unrestricted = clientCertificateExtensions("10.9.1.4", null);
  assert.match(unrestricted, /IP\.1=10\.9\.1\.4/);
  assert.doesNotMatch(unrestricted, /allowed-source-cidr/);

  const restricted = clientCertificateExtensions("10.9.1.4", "192.0.2.0/24");
  assert.match(restricted, /IP\.1=10\.9\.1\.4/);
  assert.match(restricted, /URI\.1=urn:autobricks:allowed-source-cidr:192\.0\.2\.0\/24/);
});
