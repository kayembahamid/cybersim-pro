import { createHash, createHmac, createVerify, randomUUID } from "crypto";

import type { AuditLogger } from "../utils/auditLogger.js";
import type { RoleMapper } from "./roleMapper.js";
import type { OidcConfig, SsoConfig } from "./identityConfig.js";

export interface IdentitySession {
  token: string;
  userId: string;
  email?: string;
  roles: string[];
  approvals: string[];
  groups: string[];
  issuedAt: Date;
  expiresAt: Date;
  requiresMfa: boolean;
  protocol: "oidc" | "saml";
  mfaSatisfied: boolean;
}

interface SessionRecord extends IdentitySession {
  attributes: Record<string, unknown>;
}

interface OidcJwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

interface OidcJwtPayload {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  sub?: string;
  email?: string;
  groups?: string[] | string;
  roles?: string[] | string;
  [key: string]: unknown;
}

export class AuthGateway {
  private readonly sessions = new Map<string, SessionRecord>();

  constructor(
    private readonly config: SsoConfig | undefined,
    private readonly roleMapper: RoleMapper,
    private readonly auditLogger: AuditLogger
  ) {}

  isEnabled(): boolean {
    return Boolean(this.config?.enabled);
  }

  async handleOidcCallback(idToken: string): Promise<IdentitySession> {
    if (!this.config?.enabled || !this.config?.oidc) {
      throw new Error("OIDC is not configured");
    }

    const { payload, header } = this.verifyOidcToken(idToken, this.config.oidc);
    const groups = this.extractGroups(payload);
    const { roles, approvals } = this.roleMapper.map(groups);
    const mfaSatisfied = this.isMfaSatisfied(payload);
    const requiresMfa = this.requiresMfa(roles) && !mfaSatisfied;
    const userId = (payload.sub || payload.email || "unknown-user") as string;
    const email = typeof payload.email === "string" ? payload.email : undefined;

    const session = this.createSession({
      protocol: "oidc",
      userId,
      email,
      groups,
      roles,
      approvals,
      attributes: { ...payload, header },
      requiresMfa,
      mfaSatisfied,
    });

    await this.logIdentityEvent("oidc", userId, roles, approvals, true);
    return session;
  }

  async handleSamlResponse(samlResponse: string): Promise<IdentitySession> {
    if (!this.config?.enabled || !this.config?.saml) {
      throw new Error("SAML is not configured");
    }

    const assertion = this.parseSamlResponse(samlResponse, this.config.saml);
    const { roles, approvals } = this.roleMapper.map(assertion.groups);
    const requiresMfa = this.requiresMfa(roles);

    const session = this.createSession({
      protocol: "saml",
      userId: assertion.subject,
      email: assertion.email,
      groups: assertion.groups,
      roles,
      approvals,
      attributes: assertion.attributes,
      requiresMfa,
      mfaSatisfied: false,
    });

    await this.logIdentityEvent("saml", assertion.subject, roles, approvals, true);
    return session;
  }

  getSession(token: string | undefined): IdentitySession | null {
    if (!token) return null;
    const record = this.sessions.get(token);
    if (!record) return null;
    if (record.expiresAt.getTime() < Date.now()) {
      this.sessions.delete(token);
      return null;
    }
    return { ...record };
  }

  invalidateSession(token: string): void {
    this.sessions.delete(token);
  }

  getSamlMetadata(): string | null {
    if (!this.config?.enabled || !this.config?.saml) {
      return null;
    }
    const saml = this.config.saml;
    const entityId = saml.entityId;
    const acsUrl = saml.acsUrl;
    return `<?xml version="1.0" encoding="UTF-8"?>\n<EntityDescriptor entityID="${entityId}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n    <AssertionConsumerService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acsUrl}"/>\n  </SPSSODescriptor>\n</EntityDescriptor>`;
  }

  private requiresMfa(roles: string[]): boolean {
    const enforced = this.config?.mfaEnforcedRoles ?? [];
    if (enforced.length === 0) {
      return false;
    }
    return roles.some((role) => enforced.includes(role));
  }

  private verifyOidcToken(idToken: string, oidc: OidcConfig): { payload: OidcJwtPayload; header: OidcJwtHeader } {
    const segments = idToken.split(".");
    if (segments.length !== 3) {
      throw new Error("Invalid ID token format");
    }

    const header = this.decodeJson<OidcJwtHeader>(segments[0]);
    const payload = this.decodeJson<OidcJwtPayload>(segments[1]);
    const signature = this.base64UrlDecode(segments[2]);

    const algorithm = header.alg;
    if (!algorithm) {
      throw new Error("Missing JWT algorithm");
    }

    const allowed = oidc.allowedAlgorithms ?? ["RS256", "HS256"];
    if (!allowed.includes(algorithm as any)) {
      throw new Error(`Disallowed JWT algorithm: ${algorithm}`);
    }

    const signingInput = `${segments[0]}.${segments[1]}`;
    const key = this.selectOidcKey(header.kid, algorithm, oidc);
    if (!key) {
      throw new Error("No matching key for token");
    }

    let verified = false;
    if (algorithm === "RS256" && key.pem) {
      const verifier = createVerify("RSA-SHA256");
      verifier.update(signingInput);
      verifier.end();
      verified = verifier.verify(key.pem, signature);
    } else if (algorithm === "HS256" && key.secret) {
      const computed = createHmac("sha256", key.secret).update(signingInput).digest();
      verified = this.timingSafeEqual(computed, signature);
    }

    if (!verified) {
      throw new Error("Failed to verify ID token signature");
    }

    this.validateOidcClaims(payload, oidc);
    return { payload, header };
  }

  private validateOidcClaims(payload: OidcJwtPayload, oidc: OidcConfig): void {
    if (!payload.iss || payload.iss !== oidc.issuer) {
      throw new Error("Invalid issuer");
    }

    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audience.includes(oidc.audience)) {
      throw new Error("Invalid audience");
    }

    if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp + (oidc.clockToleranceSeconds ?? 300)) {
      throw new Error("ID token has expired");
    }

    if (typeof payload.nbf === "number" && Date.now() / 1000 + (oidc.clockToleranceSeconds ?? 300) < payload.nbf) {
      throw new Error("ID token not yet valid");
    }
  }

  private selectOidcKey(kid: string | undefined, alg: string, oidc: OidcConfig) {
    if (kid) {
      const matched = oidc.publicKeys.find((key) => key.kid === kid);
      if (matched) {
        return matched;
      }
    }
    return oidc.publicKeys.find((key) => (alg === "RS256" && key.pem) || (alg === "HS256" && key.secret));
  }

  private decodeJson<T>(segment: string): T {
    const buffer = this.base64UrlDecode(segment);
    return JSON.parse(buffer.toString("utf8")) as T;
  }

  private base64UrlDecode(value: string): Buffer {
    const padding = value.length % 4 === 0 ? 0 : 4 - (value.length % 4);
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding);
    return Buffer.from(normalized, "base64");
  }

  private extractGroups(payload: OidcJwtPayload): string[] {
    const groups: string[] = [];
    const raw = payload.groups ?? payload.roles;
    if (Array.isArray(raw)) {
      for (const entry of raw) {
        if (typeof entry === "string") {
          groups.push(entry);
        }
      }
    } else if (typeof raw === "string") {
      groups.push(raw);
    }
    return groups;
  }

  private parseSamlResponse(encoded: string, saml: NonNullable<SsoConfig["saml"]>) {
    const xml = Buffer.from(encoded, "base64").toString("utf8");

    if (saml.issuer) {
      const issuerMatch = xml.match(/<Issuer[^>]*>([^<]+)<\/Issuer>/i);
      const issuer = issuerMatch ? issuerMatch[1].trim() : undefined;
      if (issuer !== saml.issuer) {
        throw new Error("Unexpected SAML issuer");
      }
    }

    if (saml.audience) {
      const audienceMatch = xml.match(/<Audience[^>]*>([^<]+)<\/Audience>/i);
      const audience = audienceMatch ? audienceMatch[1].trim() : undefined;
      if (audience !== saml.audience) {
        throw new Error("Unexpected SAML audience");
      }
    }

    const certMatch = xml.match(/<ds:X509Certificate[^>]*>([^<]+)<\/ds:X509Certificate>/i);
    if (!certMatch) {
      throw new Error("Missing SAML certificate");
    }
    const certificateBase64 = certMatch[1].replace(/\s+/g, "");

    if (Array.isArray(saml.certificateFingerprints) && saml.certificateFingerprints.length > 0) {
      const der = Buffer.from(certificateBase64, "base64");
      const normalizedAllowed = saml.certificateFingerprints.map((fp) => fp.replace(/[^a-fA-F0-9]/g, "").toLowerCase());
      const sha1 = createHash("sha1").update(der).digest("hex");
      const sha256 = createHash("sha256").update(der).digest("hex");
      if (!normalizedAllowed.includes(sha1) && !normalizedAllowed.includes(sha256)) {
        throw new Error("Unrecognised SAML certificate fingerprint");
      }
    }

    const certificatePem = this.buildCertificatePem(certificateBase64);
    this.verifySamlSignature(xml, certificatePem);
    this.validateSamlConditions(xml);

    const subjectMatch = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/i);
    if (!subjectMatch) {
      throw new Error("Missing SAML NameID");
    }
    const subject = subjectMatch[1].trim();

    const attributes = this.extractSamlAttributes(xml);
    const email = this.pickAttribute(attributes, ["email", "mail", "emailaddress"]);
    const rawGroups = this.collectAttributeValues(attributes, ["groups", "group", "memberof", "roles"]);
    const groups = rawGroups.map((value) => value.trim()).filter(Boolean);

    return {
      subject,
      email,
      groups,
      attributes,
    };
  }

  private extractSamlAttributes(xml: string): Record<string, string[]> {
    const attributes: Record<string, string[]> = {};
    const attributeRegex = /<Attribute[^>]*Name="([^"]+)"[^>]*>([\s\S]*?)<\/Attribute>/gi;
    let match: RegExpExecArray | null;
    while ((match = attributeRegex.exec(xml)) !== null) {
      const name = match[1];
      const values: string[] = [];
      const valueBlock = match[2];
      const valueRegex = /<AttributeValue[^>]*>([\s\S]*?)<\/AttributeValue>/gi;
      let valueMatch: RegExpExecArray | null;
      while ((valueMatch = valueRegex.exec(valueBlock)) !== null) {
        const value = valueMatch[1].replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1").trim();
        if (value) {
          values.push(value);
        }
      }
      if (!attributes[name]) {
        attributes[name] = [];
      }
      attributes[name].push(...values);
    }
    return attributes;
  }

  private pickAttribute(attributes: Record<string, string[]>, keys: string[]): string | undefined {
    for (const key of keys) {
      const found = attributes[key] || attributes[key.toUpperCase()] || attributes[key.toLowerCase()];
      if (found && found.length > 0) {
        return found[0];
      }
    }
    return undefined;
  }

  private collectAttributeValues(attributes: Record<string, string[]>, keys: string[]): string[] {
    const collected: string[] = [];
    for (const key of keys) {
      const variants = [key, key.toUpperCase(), key.toLowerCase()];
      for (const variant of variants) {
        const values = attributes[variant];
        if (Array.isArray(values)) {
          collected.push(...values);
        }
      }
    }
    return collected;
  }

  private timingSafeEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i += 1) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  private createSession(input: {
    protocol: "oidc" | "saml";
    userId: string;
    email?: string;
    roles: string[];
    approvals: string[];
    groups: string[];
    attributes: Record<string, unknown>;
    requiresMfa: boolean;
    mfaSatisfied: boolean;
  }): IdentitySession {
    const ttlMinutes = this.config?.sessionTtlMinutes ?? 60;
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + ttlMinutes * 60 * 1000);
    const token = randomUUID();

    const record: SessionRecord = {
      token,
      userId: input.userId,
      email: input.email,
      roles: input.roles,
      approvals: input.approvals,
      groups: input.groups,
      issuedAt,
      expiresAt,
      requiresMfa: input.requiresMfa,
      mfaSatisfied: input.mfaSatisfied,
      protocol: input.protocol,
      attributes: input.attributes,
    };

    this.sessions.set(token, record);
    return { ...record };
  }

  private async logIdentityEvent(
    protocol: "oidc" | "saml",
    userId: string,
    roles: string[],
    approvals: string[],
    success: boolean
  ): Promise<void> {
    await this.auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: protocol === "oidc" ? "identity_oidc" : "identity_saml",
      status: success ? "success" : "error",
      durationMs: 0,
      metadata: {
        userId,
        roles,
        approvals,
      },
    });
  }

  private isMfaSatisfied(payload: OidcJwtPayload): boolean {
    const config = this.config?.oidc;
    const amrConfigured = config?.mfaSatisfiedAmrValues?.map((value) => value.toLowerCase());
    const acrConfigured = config?.mfaSatisfiedAcrValues?.map((value) => value.toLowerCase());

    const defaultAmr = ["mfa", "otp", "hardware", "hwk", "sms", "email"];
    const amrValues = amrConfigured && amrConfigured.length > 0 ? amrConfigured : defaultAmr;

    const amrClaim = (payload as Record<string, unknown>).amr;
    if (Array.isArray(amrClaim)) {
      const normalized = amrClaim.map((value) => String(value).toLowerCase());
      if (normalized.some((value) => amrValues.includes(value))) {
        return true;
      }
    } else if (typeof amrClaim === "string") {
      if (amrValues.includes(amrClaim.toLowerCase())) {
        return true;
      }
    }

    if (typeof payload.acr === "string") {
      const acrValue = payload.acr.toLowerCase();
      if (acrConfigured && acrConfigured.length > 0) {
        if (acrConfigured.includes(acrValue)) {
          return true;
        }
      } else if (acrValue.includes("mfa") || acrValue.includes("strong")) {
        return true;
      }
    }

    const mfaFlag = (payload as Record<string, unknown>).mfa;
    if (mfaFlag === true || mfaFlag === "true") {
      return true;
    }

    return false;
  }

  private buildCertificatePem(base64: string): string {
    const lines = base64.replace(/\s+/g, "").match(/.{1,64}/g) ?? [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
  }

  private verifySamlSignature(xml: string, certificatePem: string): void {
    const signedInfoMatch = xml.match(/<ds:SignedInfo[\s\S]*?<\/ds:SignedInfo>/i);
    const signatureValueMatch = xml.match(/<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/i);

    if (!signedInfoMatch || !signatureValueMatch) {
      throw new Error("Missing signature elements in SAML response");
    }

    const canonicalSignedInfo = this.canonicalizeXml(signedInfoMatch[0]);
    const signatureBuffer = Buffer.from(signatureValueMatch[1].replace(/\s+/g, ""), "base64");

    const algorithm = this.extractSignatureAlgorithm(signedInfoMatch[0]);
    const verifier = createVerify(algorithm);
    verifier.update(canonicalSignedInfo);
    verifier.end();

    if (!verifier.verify(certificatePem, signatureBuffer)) {
      throw new Error("SAML signature verification failed");
    }
  }

  private canonicalizeXml(fragment: string): string {
    return fragment
      .replace(/\r\n?/g, "\n")
      .replace(/>\s+</g, "><")
      .trim();
  }

  private extractSignatureAlgorithm(signedInfo: string): string {
    const methodMatch = signedInfo.match(/<ds:SignatureMethod[^>]*Algorithm="([^"]+)"/i);
    const algorithm = methodMatch ? methodMatch[1].toLowerCase() : "";

    if (algorithm.includes("rsa-sha256")) {
      return "RSA-SHA256";
    }
    if (algorithm.includes("rsa-sha1")) {
      return "RSA-SHA1";
    }

    throw new Error(`Unsupported SAML signature algorithm: ${algorithm || "unknown"}`);
  }

  private validateSamlConditions(xml: string): void {
    const toleranceMs = 5 * 60 * 1000;
    const now = Date.now();

    const conditionsMatch = xml.match(/<(?:saml2?:)?Conditions[^>]*>/i);
    if (conditionsMatch) {
      const notBeforeMatch = conditionsMatch[0].match(/NotBefore="([^"]+)"/i);
      const notOnOrAfterMatch = conditionsMatch[0].match(/NotOnOrAfter="([^"]+)"/i);
      if (notBeforeMatch) {
        const notBefore = Date.parse(notBeforeMatch[1]);
        if (!Number.isNaN(notBefore) && now + toleranceMs < notBefore) {
          throw new Error("SAML assertion not yet valid (NotBefore)");
        }
      }
      if (notOnOrAfterMatch) {
        const notOnOrAfter = Date.parse(notOnOrAfterMatch[1]);
        if (!Number.isNaN(notOnOrAfter) && now - toleranceMs >= notOnOrAfter) {
          throw new Error("SAML assertion has expired (NotOnOrAfter)");
        }
      }
    }

    const scdRegex = /<SubjectConfirmationData[^>]*>/gi;
    let scdMatch: RegExpExecArray | null;
    while ((scdMatch = scdRegex.exec(xml)) !== null) {
      const notOnOrAfterMatch = scdMatch[0].match(/NotOnOrAfter="([^"]+)"/i);
      if (notOnOrAfterMatch) {
        const expiry = Date.parse(notOnOrAfterMatch[1]);
        if (!Number.isNaN(expiry) && now - toleranceMs >= expiry) {
          throw new Error("SAML subject confirmation has expired");
        }
      }
    }
  }
}
