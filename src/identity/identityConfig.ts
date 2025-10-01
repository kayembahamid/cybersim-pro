import fs from "fs";
import path from "path";

export interface OidcPublicKey {
  kid?: string;
  pem?: string;
  secret?: string;
}

export interface OidcConfig {
  issuer: string;
  audience: string;
  publicKeys: OidcPublicKey[];
  allowedAlgorithms?: Array<"RS256" | "HS256">;
  clockToleranceSeconds?: number;
  mfaSatisfiedAmrValues?: string[];
  mfaSatisfiedAcrValues?: string[];
}

export interface SamlConfig {
  entityId: string;
  acsUrl: string;
  audience?: string;
  issuer?: string;
  certificateFingerprints?: string[];
}

export interface SsoConfig {
  enabled: boolean;
  protocol?: "saml" | "oidc" | "hybrid";
  saml?: SamlConfig;
  oidc?: OidcConfig;
  sessionTtlMinutes?: number;
  mfaEnforcedRoles?: string[];
}

export interface ScimConfig {
  enabled: boolean;
  baseUrl?: string;
  bearerToken?: string;
}

export interface IdentityConfig {
  sso?: SsoConfig;
  scim?: ScimConfig;
  roleMappingsPath?: string;
}

export function loadIdentityConfig(rootDir = process.cwd()): IdentityConfig {
  const serverJsonPath = path.join(rootDir, "server.json");
  if (!fs.existsSync(serverJsonPath)) {
    return {};
  }

  try {
    const content = fs.readFileSync(serverJsonPath, "utf8");
    const parsed = JSON.parse(content) as { identity?: IdentityConfig };
    const identity = parsed.identity ?? {};

    if (identity.roleMappingsPath) {
      identity.roleMappingsPath = path.resolve(rootDir, identity.roleMappingsPath);
    }

    return identity;
  } catch (error) {
    console.warn("[CyberSim] Failed to load identity config:", error);
    return {};
  }
}
