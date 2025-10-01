import type { OperatorContext } from "./accessControl.js";
import type { IdentitySession } from "../identity/authGateway.js";

type ProvenanceSource = "identity" | "operator" | "anonymous";

export interface IdentityProvenanceSnapshot {
  userId: string;
  roles: string[];
  approvals: string[];
  protocol: IdentitySession["protocol"];
  mfaSatisfied: boolean;
  email?: string;
}

export interface ExecutionProvenance {
  actorId?: string;
  actorRole?: string;
  recordedAt: string;
  source: ProvenanceSource;
  operator?: OperatorContext;
  identity?: IdentityProvenanceSnapshot;
}

export interface ExecutionContext {
  actorId?: string;
  actorRole?: string;
  operator?: OperatorContext;
  identity?: IdentityProvenanceSnapshot;
  provenance: ExecutionProvenance;
}

export function buildExecutionContext(
  operator: OperatorContext | undefined,
  session: IdentitySession | null | undefined
): ExecutionContext {
  const recordedAt = new Date().toISOString();

  if (session) {
    const identity: IdentityProvenanceSnapshot = {
      userId: session.userId,
      email: session.email,
      roles: session.roles,
      approvals: session.approvals,
      protocol: session.protocol,
      mfaSatisfied: session.mfaSatisfied,
    };
    return {
      actorId: session.userId,
      actorRole: session.roles[0],
      operator,
      identity,
      provenance: {
        actorId: session.userId,
        actorRole: session.roles[0],
        recordedAt,
        source: "identity",
        operator,
        identity,
      },
    };
  }

  if (operator?.id || operator?.role || operator?.approvals) {
    return {
      actorId: operator.id,
      actorRole: operator.role,
      operator,
      provenance: {
        actorId: operator.id,
        actorRole: operator.role,
        recordedAt,
        source: "operator",
        operator,
      },
    };
  }

  return {
    actorId: undefined,
    actorRole: undefined,
    operator,
    provenance: {
      recordedAt,
      source: "anonymous",
      operator,
    },
  };
}
