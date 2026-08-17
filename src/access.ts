/**
 * Milestone 1 — organizations, roles, and tenant isolation.
 *
 * The design decision that matters:
 *
 *   THERE IS NO WAY TO READ ORG DATA WITHOUT NAMING AN ACTOR.
 *
 * Every path into tenant-scoped data goes through `Access.org(orgId)`, which
 * resolves the caller's membership first and throws if there is none. A caller
 * cannot "forget" the authorization check, because the check is what produces
 * the object that has the query methods on it. Passing an arbitrary org_id is
 * not a bypass — it is the exact input the check consumes.
 *
 * This is the application-layer shape of what Supabase enforces with row-level
 * security. Keeping the same shape in both places means the RLS policies are a
 * translation of this file rather than a second, divergent implementation —
 * and until RLS is written, the isolation is already tested here.
 *
 * Roles are a total order for capability purposes (owner > admin > member), but
 * capabilities are declared explicitly rather than derived from the order, so a
 * future role that is not a simple superset does not break the model.
 */

import type { DatabaseSync } from 'node:sqlite';

export type Role = 'owner' | 'admin' | 'member';

export type Capability =
  | 'org.delete'
  | 'org.rename'
  | 'member.invite'
  | 'member.remove'
  | 'member.setRole'
  | 'document.upload'
  | 'document.read'
  | 'document.delete'
  | 'rules.edit'
  | 'billing.manage';

/** Explicit matrix. Adding a role means adding a column, not editing logic. */
const CAPABILITIES: Record<Role, ReadonlySet<Capability>> = {
  owner: new Set<Capability>([
    'org.delete', 'org.rename', 'member.invite', 'member.remove',
    'member.setRole', 'document.upload', 'document.read', 'document.delete',
    'rules.edit', 'billing.manage',
  ]),
  admin: new Set<Capability>([
    'org.rename', 'member.invite', 'member.remove',
    'document.upload', 'document.read', 'document.delete', 'rules.edit',
  ]),
  member: new Set<Capability>([
    'document.upload', 'document.read',
  ]),
};

export class AuthorizationError extends Error {
  readonly code = 'FORBIDDEN';
  constructor(message: string) { super(message); this.name = 'AuthorizationError'; }
}

export class LimitExceededError extends Error {
  readonly code = 'LIMIT_EXCEEDED';
  constructor(message: string) { super(message); this.name = 'LimitExceededError'; }
}

export interface OrgSummary { id: number; slug: string; name: string; role: Role }

/**
 * Scope object. Its existence is proof that the caller is a member of the org,
 * so nothing downstream re-checks membership — it re-checks only capability.
 */
export class OrgScope {
  private db: DatabaseSync;
  readonly userId: number;
  readonly orgId: number;
  readonly role: Role;

  constructor(db: DatabaseSync, userId: number, orgId: number, role: Role) {
    this.db = db;
    this.userId = userId;
    this.orgId = orgId;
    this.role = role;
  }

  can(cap: Capability): boolean {
    return CAPABILITIES[this.role].has(cap);
  }

  require(cap: Capability): void {
    if (!this.can(cap)) {
      throw new AuthorizationError(
        `role '${this.role}' lacks capability '${cap}' in org ${this.orgId}`);
    }
  }

  // ------------------------------------------------------------- membership

  members(): { user_id: number; email: string; role: Role }[] {
    return this.db.prepare(
      `SELECT m.user_id, u.email, m.role
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? ORDER BY m.id`
    ).all(this.orgId) as { user_id: number; email: string; role: Role }[];
  }

  invite(targetUserId: number, role: Role): void {
    this.require('member.invite');
    // An admin cannot mint an owner — privilege escalation by invitation is the
    // classic hole in this shape.
    if (role === 'owner' && this.role !== 'owner') {
      throw new AuthorizationError('only an owner can grant the owner role');
    }
    this.db.prepare(
      `INSERT INTO memberships (user_id, org_id, role) VALUES (?, ?, ?)
       ON CONFLICT (user_id, org_id) DO NOTHING`
    ).run(targetUserId, this.orgId, role);
  }

  setRole(targetUserId: number, role: Role): void {
    this.require('member.setRole');
    if (targetUserId === this.userId && role !== 'owner') {
      this.assertNotLastOwner(targetUserId);
    }
    this.db.prepare(
      'UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?'
    ).run(role, this.orgId, targetUserId);
  }

  remove(targetUserId: number): void {
    this.require('member.remove');
    const target = this.roleOf(targetUserId);
    if (!target) return;
    // An admin cannot remove an owner: capability alone is not enough when the
    // target outranks the actor.
    if (target === 'owner' && this.role !== 'owner') {
      throw new AuthorizationError('an admin cannot remove an owner');
    }
    this.assertNotLastOwner(targetUserId);
    this.db.prepare(
      'DELETE FROM memberships WHERE org_id = ? AND user_id = ?'
    ).run(this.orgId, targetUserId);
  }

  private roleOf(userId: number): Role | null {
    const r = this.db.prepare(
      'SELECT role FROM memberships WHERE org_id = ? AND user_id = ?'
    ).get(this.orgId, userId) as { role: Role } | undefined;
    return r?.role ?? null;
  }

  /** An org with zero owners is unadministrable, so the last one cannot leave. */
  private assertNotLastOwner(userId: number): void {
    const isOwner = this.roleOf(userId) === 'owner';
    if (!isOwner) return;
    const n = this.db.prepare(
      `SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner'`
    ).get(this.orgId) as { n: number };
    if (n.n <= 1) {
      throw new AuthorizationError(
        'cannot remove or demote the last owner — transfer ownership first');
    }
  }

  // ------------------------------------------------------------- documents

  /**
   * Tenant-scoped read. The org_id filter is applied here and is not a caller
   * argument, which is the whole point — there is no overload that takes an
   * org_id from outside.
   */
  documents(): { id: number; filename: string; status: string }[] {
    this.require('document.read');
    return this.db.prepare(
      `SELECT id, filename, status FROM documents WHERE org_id = ? ORDER BY id`
    ).all(String(this.orgId)) as { id: number; filename: string; status: string }[];
  }

  /** Returns null for a document in another org — indistinguishable from absent. */
  document(documentId: number): { id: number; filename: string } | null {
    this.require('document.read');
    const row = this.db.prepare(
      'SELECT id, filename FROM documents WHERE id = ? AND org_id = ?'
    ).get(documentId, String(this.orgId)) as { id: number; filename: string } | undefined;
    return row ?? null;
  }

  /**
   * Reserve one unit of quota and register the document in one transaction, so
   * two concurrent uploads cannot both fit under a limit that admits one.
   */
  reserveUpload(period: string): void {
    this.require('document.upload');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare(
        `INSERT INTO usage_counters (org_id, period, documents)
         VALUES (?, ?, 0) ON CONFLICT (org_id, period) DO NOTHING`
      ).run(this.orgId, period);
      const row = this.db.prepare(
        'SELECT documents, doc_limit FROM usage_counters WHERE org_id = ? AND period = ?'
      ).get(this.orgId, period) as { documents: number; doc_limit: number };
      if (row.documents >= row.doc_limit) {
        throw new LimitExceededError(
          `org ${this.orgId} reached ${row.doc_limit} documents for ${period}`);
      }
      this.db.prepare(
        'UPDATE usage_counters SET documents = documents + 1 WHERE org_id = ? AND period = ?'
      ).run(this.orgId, period);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  usage(period: string): { documents: number; doc_limit: number } {
    const row = this.db.prepare(
      'SELECT documents, doc_limit FROM usage_counters WHERE org_id = ? AND period = ?'
    ).get(this.orgId, period) as { documents: number; doc_limit: number } | undefined;
    return row ?? { documents: 0, doc_limit: 50 };
  }

  setLimit(period: string, limit: number): void {
    this.require('billing.manage');
    this.db.prepare(
      `INSERT INTO usage_counters (org_id, period, documents, doc_limit)
       VALUES (?, ?, 0, ?)
       ON CONFLICT (org_id, period) DO UPDATE SET doc_limit = excluded.doc_limit`
    ).run(this.orgId, period, limit);
  }
}

/** Entry point. Constructed from an authenticated identity, never from an org. */
export class Access {
  private db: DatabaseSync;
  readonly userId: number;

  constructor(db: DatabaseSync, userId: number) {
    this.db = db;
    this.userId = userId;
  }

  static forSubject(db: DatabaseSync, authSubject: string, email: string): Access {
    const existing = db.prepare(
      'SELECT id FROM users WHERE auth_subject = ?'
    ).get(authSubject) as { id: number } | undefined;
    if (existing) return new Access(db, existing.id);
    const info = db.prepare(
      'INSERT INTO users (auth_subject, email) VALUES (?, ?)'
    ).run(authSubject, email);
    return new Access(db, Number(info.lastInsertRowid));
  }

  /** Create an org and become its owner, atomically. */
  createOrg(slug: string, name: string): OrgScope {
    this.db.exec('BEGIN');
    try {
      const info = this.db.prepare(
        'INSERT INTO organizations (slug, name) VALUES (?, ?)'
      ).run(slug, name);
      const orgId = Number(info.lastInsertRowid);
      this.db.prepare(
        `INSERT INTO memberships (user_id, org_id, role) VALUES (?, ?, 'owner')`
      ).run(this.userId, orgId);
      this.db.exec('COMMIT');
      return new OrgScope(this.db, this.userId, orgId, 'owner');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  /** THE isolation gate. No membership row, no scope, no data. */
  org(orgId: number): OrgScope {
    const row = this.db.prepare(
      'SELECT role FROM memberships WHERE user_id = ? AND org_id = ?'
    ).get(this.userId, orgId) as { role: Role } | undefined;
    if (!row) {
      // Deliberately identical to the message for a nonexistent org: a probe
      // must not learn whether org 42 exists.
      throw new AuthorizationError(`no access to org ${orgId}`);
    }
    return new OrgScope(this.db, this.userId, orgId, row.role);
  }

  /** Orgs this user belongs to — the only listing that exists. */
  organizations(): OrgSummary[] {
    return this.db.prepare(
      `SELECT o.id, o.slug, o.name, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? ORDER BY o.id`
    ).all(this.userId) as OrgSummary[];
  }
}
