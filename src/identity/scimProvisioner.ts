import { randomUUID } from "crypto";

import type { AuditLogger } from "../utils/auditLogger.js";
import type { ScimConfig } from "./identityConfig.js";

export interface ScimUser {
  id: string;
  userName: string;
  active: boolean;
  emails?: Array<{ value: string; primary?: boolean }>;
  groups?: Array<{ value: string; display?: string }>;
  raw?: Record<string, unknown>;
}

export interface ScimGroup {
  id: string;
  displayName: string;
  members: Array<{ value: string; display?: string }>;
  raw?: Record<string, unknown>;
}

export class ScimProvisioner {
  private readonly users = new Map<string, ScimUser>();
  private readonly groups = new Map<string, ScimGroup>();

  constructor(
    private readonly config: ScimConfig | undefined,
    private readonly auditLogger: AuditLogger
  ) {}

  isEnabled(): boolean {
    return Boolean(this.config?.enabled);
  }

  getBearerToken(): string | undefined {
    return this.config?.bearerToken;
  }

  getBaseUrl(): string | undefined {
    return this.config?.baseUrl;
  }

  listUsers(): ScimUser[] {
    return Array.from(this.users.values());
  }

  listGroups(): ScimGroup[] {
    return Array.from(this.groups.values());
  }

  getUser(id: string): ScimUser | undefined {
    return this.users.get(id);
  }

  getGroup(id: string): ScimGroup | undefined {
    return this.groups.get(id);
  }

  upsertUser(payload: Partial<ScimUser> & { userName: string }, actor: string): ScimUser {
    const id = payload.id || randomUUID();
    const user: ScimUser = {
      id,
      userName: payload.userName,
      active: payload.active ?? true,
      emails: payload.emails,
      groups: payload.groups ?? [],
      raw: payload.raw ?? {},
    };
    this.users.set(id, user);
    void this.logProvisioning("user", actor, user.id, user.userName, user.active);
    return user;
  }

  deactivateUser(id: string, actor: string): ScimUser | undefined {
    const existing = this.users.get(id);
    if (!existing) return undefined;
    existing.active = false;
    this.users.set(id, existing);
    void this.logProvisioning("user", actor, existing.id, existing.userName, false);
    return existing;
  }

  upsertGroup(payload: Partial<ScimGroup> & { displayName: string }, actor: string): ScimGroup {
    const id = payload.id || randomUUID();
    const group: ScimGroup = {
      id,
      displayName: payload.displayName,
      members: payload.members ?? [],
      raw: payload.raw ?? {},
    };
    this.groups.set(id, group);
    this.updateUserMembershipFromGroup(group);
    void this.logProvisioning("group", actor, group.id, group.displayName, true);
    return group;
  }

  removeGroup(id: string, actor: string): void {
    const group = this.groups.get(id);
    if (!group) return;
    this.groups.delete(id);
    for (const user of this.users.values()) {
      if (!Array.isArray(user.groups)) continue;
      user.groups = user.groups.filter((entry) => entry.value !== id);
    }
    void this.logProvisioning("group", actor, id, group.displayName, false);
  }

  private updateUserMembershipFromGroup(group: ScimGroup): void {
    for (const member of group.members) {
      const user = this.users.get(member.value);
      if (!user) continue;
      const memberships = user.groups ?? [];
      const exists = memberships.some((entry) => entry.value === group.id);
      if (!exists) {
        memberships.push({ value: group.id, display: group.displayName });
      }
      user.groups = memberships;
      this.users.set(user.id, user);
    }
  }

  private async logProvisioning(
    resourceType: "user" | "group",
    actor: string,
    id: string,
    name: string,
    active: boolean
  ): Promise<void> {
    await this.auditLogger.log({
      timestamp: new Date().toISOString(),
      tool: "scim_provisioning",
      status: "success",
      durationMs: 0,
      metadata: {
        resourceType,
        id,
        name,
        actor,
        active,
      },
    });
  }
}
