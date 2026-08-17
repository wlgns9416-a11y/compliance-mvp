/**
 * M1 observation: multi-tenant isolation and role separation.
 *
 * The assertion that decides the milestone is `ISOLATION` — a member of org B
 * cannot reach org A's documents by any route the API exposes, including
 * passing org A's id directly.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { Pipeline } from '../src/pipeline.ts';
import { Access, AuthorizationError, LimitExceededError, OrgScope } from '../src/access.ts';

const PERIOD = '2026-08';

function setup() {
  const p = new Pipeline(':memory:', { backoffSeconds: 0 });
  const alice = Access.forSubject(p.db, 'auth|alice', 'alice@acme.test');
  const bob = Access.forSubject(p.db, 'auth|bob', 'bob@globex.test');
  const carol = Access.forSubject(p.db, 'auth|carol', 'carol@acme.test');
  const acme = alice.createOrg('acme', 'Acme Inc');
  const globex = bob.createOrg('globex', 'Globex LLC');
  return { p, alice, bob, carol, acme, globex };
}

test('creating an org makes the creator its owner', () => {
  const { alice, acme } = setup();
  assert.equal(acme.role, 'owner');
  const orgs = alice.organizations();
  assert.equal(orgs.length, 1);
  assert.equal(orgs[0].role, 'owner');
});

test('a user belongs to multiple orgs with independent roles', () => {
  const { alice, bob, carol } = setup();
  const a = alice.organizations()[0];
  const g = bob.organizations()[0];

  alice.org(a.id).invite(carol.userId, 'admin');
  bob.org(g.id).invite(carol.userId, 'member');

  const orgs = carol.organizations();
  assert.equal(orgs.length, 2);
  assert.deepEqual(orgs.map(o => o.role).sort(), ['admin', 'member']);
});

test('ISOLATION — an outsider cannot reach another org by passing its id', () => {
  const { p, alice, bob, acme, globex } = setup();
  p.ingest(String(acme.orgId), 'acme-secret.pdf', 'SECRET-A');
  p.ingest(String(globex.orgId), 'globex-notes.pdf', 'NOTES-B');

  // Own org: visible.
  assert.equal(acme.documents().length, 1);
  assert.equal(acme.documents()[0].filename, 'acme-secret.pdf');

  // Other org by direct id: refused at the gate, before any query runs.
  assert.throws(() => bob.org(acme.orgId), AuthorizationError);
  assert.throws(() => alice.org(globex.orgId), AuthorizationError);

  // And the error must not disclose existence — same message shape as an org
  // that does not exist at all.
  const real = (() => { try { bob.org(acme.orgId); } catch (e) { return (e as Error).message; } })();
  const fake = (() => { try { bob.org(999999); } catch (e) { return (e as Error).message; } })();
  assert.equal(real.replace(/\d+/, 'N'), fake.replace(/\d+/, 'N'),
    'membership failure and nonexistent org must be indistinguishable');
});

test('ISOLATION — a document id from another org reads as absent, not as denied', () => {
  const { p, bob, acme, globex } = setup();
  const docId = p.ingest(String(acme.orgId), 'acme-secret.pdf', 'SECRET-A');
  assert.equal(globex.document(docId), null,
    'cross-tenant document lookup must return null');
});

test('role capabilities are enforced, not advisory', () => {
  const { alice, carol, acme } = setup();
  acme.invite(carol.userId, 'member');
  const carolScope = carol.org(acme.orgId);

  assert.ok(carolScope.can('document.upload'));
  assert.ok(carolScope.can('document.read'));
  assert.ok(!carolScope.can('member.remove'));
  assert.ok(!carolScope.can('org.delete'));

  assert.throws(() => carolScope.remove(alice.userId), AuthorizationError);
  assert.throws(() => carolScope.setLimit(PERIOD, 999), AuthorizationError);
});

test('an admin cannot mint an owner or remove one', () => {
  const { p, alice, carol, acme } = setup();
  const dave = Access.forSubject(p.db, 'auth|dave', 'dave@acme.test');
  acme.invite(carol.userId, 'admin');
  const carolScope = carol.org(acme.orgId);

  assert.throws(() => carolScope.invite(dave.userId, 'owner'), AuthorizationError,
    'privilege escalation by invitation must be blocked');
  assert.throws(() => carolScope.remove(alice.userId), AuthorizationError,
    'an admin must not be able to remove an owner');

  carolScope.invite(dave.userId, 'member');
  assert.equal(acme.members().length, 3);
});

test('the last owner cannot be removed or demoted', () => {
  const { carol, acme } = setup();
  acme.invite(carol.userId, 'admin');

  assert.throws(() => acme.setRole(acme.userId, 'member'), AuthorizationError);
  assert.throws(() => acme.remove(acme.userId), AuthorizationError);

  // Promote a second owner, then the first may step down.
  acme.setRole(carol.userId, 'owner');
  acme.setRole(acme.userId, 'member');
  const roles = acme.members().map(m => m.role).sort();
  assert.deepEqual(roles, ['member', 'owner']);
});

test('usage limit is enforced per org and per period', () => {
  const { acme, globex } = setup();
  acme.setLimit(PERIOD, 2);

  acme.reserveUpload(PERIOD);
  acme.reserveUpload(PERIOD);
  assert.throws(() => acme.reserveUpload(PERIOD), LimitExceededError);

  assert.equal(acme.usage(PERIOD).documents, 2, 'a rejected upload must not consume quota');

  // A different org is unaffected; a different period starts fresh.
  globex.reserveUpload(PERIOD);
  assert.equal(globex.usage(PERIOD).documents, 1);
  acme.reserveUpload('2026-09');
  assert.equal(acme.usage('2026-09').documents, 1);
});

test('pipeline data stays inside its org across the full M1+M2 path', async () => {
  const { p, acme, globex } = setup();

  const docId = p.ingest(String(acme.orgId), 'contract.pdf', 'BYTES');
  p.addRule({ id: 'DR-01', org_id: String(acme.orgId), title: 'Indefinite retention',
              severity: 'critical', pattern: 'indefinitely' });
  p.extractAndChunk(docId, [
    { page: 1, text: 'data retained indefinitely by the vendor' },
    { page: 2, text: 'ordinary clause text' },
  ]);
  await p.run(docId, {
    async analyze(chunk, rules) {
      return rules.filter(r => chunk.text.includes(r.pattern)).map(r => ({
        rule_id: r.id, severity: r.severity, message: r.title, page_ref: chunk.page_start,
      }));
    },
  });

  assert.ok(p.findingCount(docId) > 0);
  assert.equal(acme.documents().length, 1);
  assert.equal(globex.documents().length, 0, 'the other tenant sees nothing');
  assert.equal(globex.document(docId), null);
});
