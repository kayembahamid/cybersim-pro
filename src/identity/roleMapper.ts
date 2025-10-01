import fs from "fs";

export interface RoleMappingDefinition {
  id: string;
  roles: string[];
  approvalRequired?: boolean;
}

export class RoleMapper {
  private readonly mappings: RoleMappingDefinition[] = [];

  constructor(roleMappingsPath?: string) {
    if (roleMappingsPath && fs.existsSync(roleMappingsPath)) {
      try {
        const content = fs.readFileSync(roleMappingsPath, "utf8");
        const parsed = JSON.parse(content) as RoleMappingDefinition[];
        this.mappings = parsed;
      } catch (error) {
        console.warn("[CyberSim] Failed to parse role mappings:", error);
      }
    }
  }

  map(groups: string[] = []): { roles: string[]; approvals: string[] } {
    const roles = new Set<string>();
    const approvals = new Set<string>();

    for (const mapping of this.mappings) {
      if (groups.includes(mapping.id)) {
        for (const role of mapping.roles) {
          roles.add(role);
        }
        if (mapping.approvalRequired) {
          approvals.add(mapping.id);
        }
      }
    }

    return {
      roles: Array.from(roles),
      approvals: Array.from(approvals),
    };
  }
}
