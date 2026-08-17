/**
 * The observation that decides whether the design works.
 *
 * Scenario is the one from the job post, verbatim: a 150-page PDF, extraction
 * succeeds, analysis fails halfway. The assertions check that a resume
 * processes ONLY the failed chunks and produces no duplicate findings.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { Pipeline, type Analyzer, type Chunk, type Finding, type Page, type RuleRow }
  from '../src/pipeline.ts';

function makePages(n: number): Page[] {
  return Array.from({ length: n }, (_, i) => ({
    page: i + 1,
    text: `Section ${i + 1}. This agreement shall retain personal data indefinitely `
        + `and the vendor may process information without notice. `
        + `Clause body text for page ${i + 1}. `.repeat(6),
  }));
}

const RULES: Omit<RuleRow, 'enabled'>[] = [
  { id: 'DR-01', org_id: 'org1', title: 'Indefinite retention', severity: 'critical', pattern: 'indefinitely' },
  { id: 'DR-02', org_id: 'org1', title: 'Processing without notice', severity: 'warning', pattern: 'without notice' },
];

/** Deterministic stand-in for the model call. Failure is injected, not random. */
class FakeAnalyzer implements Analyzer {
  calls = 0;
  seen: number[] = [];
  failOn: (chunk: Chunk) => boolean;

  constructor(failOn: (chunk: Chunk) => boolean) {
    this.failOn = failOn;
  }

  async analyze(chunk: Chunk, rules: RuleRow[]): Promise<Finding[]> {
    this.calls++;
    this.seen.push(chunk.seq);
    if (this.failOn(chunk)) throw new Error(`upstream 503 on seq ${chunk.seq}`);
    const out: Finding[] = [];
    for (const r of rules) {
      if (chunk.text.includes(r.pattern)) {
        out.push({
          rule_id: r.id,
          severity: r.severity,
          message: `${r.title} detected`,
          page_ref: chunk.page_start,
          excerpt: r.pattern,
        });
      }
    }
    return out;
  }
}

function setup() {
  const p = new Pipeline(':memory:', { maxAttempts: 3, chunkTargetChars: 2000, backoffSeconds: 0 });
  RULES.forEach(r => p.addRule(r));
  const docId = p.ingest('org1', 'contract-150p.pdf', 'BYTES-A');
  const n = p.extractAndChunk(docId, makePages(150));
  return { p, docId, n };
}

test('150-page document chunks with page provenance preserved', () => {
  const { p, docId, n } = setup();
  assert.ok(n > 20, `expected many chunks, got ${n}`);
  const rows = p.db.prepare(
    'SELECT page_start, page_end FROM chunks WHERE document_id = ? ORDER BY seq'
  ).all(docId) as { page_start: number; page_end: number }[];
  assert.equal(rows[0].page_start, 1);
  assert.equal(rows.at(-1)!.page_end, 150);
  for (const r of rows) assert.ok(r.page_start <= r.page_end);
});

test('extraction is not repeated on a second call', () => {
  const { p, docId, n } = setup();
  const again = p.extractAndChunk(docId, makePages(150));
  assert.equal(again, n, 'chunk count must be stable');
  const total = p.db.prepare(
    'SELECT COUNT(*) AS n FROM chunks WHERE document_id = ?'
  ).get(docId) as { n: number };
  assert.equal(total.n, n, 'no duplicate chunks written');
});

test('re-upload of identical bytes returns the same document', () => {
  const { p, docId } = setup();
  const second = p.ingest('org1', 'contract-150p.pdf', 'BYTES-A');
  assert.equal(second, docId);
});

test('THE CASE — analysis fails halfway, resume processes only the failures', async () => {
  const { p, docId, n } = setup();
  const half = Math.floor(n / 2);

  // Run 1: every chunk from the midpoint on fails.
  const a1 = new FakeAnalyzer(c => c.seq >= half);
  const r1 = await p.run(docId, a1);

  assert.equal(r1.chunksTotal, n);
  assert.equal(r1.outcome, 'partial');
  assert.equal(r1.chunksDone, half, 'first half should have succeeded');
  assert.ok(r1.chunksFailed > 0);
  const findingsAfterRun1 = p.findingCount(docId);
  assert.ok(findingsAfterRun1 > 0);

  // Run 2: upstream recovered. Same entry point, no "resume" flag anywhere.
  const a2 = new FakeAnalyzer(() => false);
  const r2 = await p.run(docId, a2);

  // ---- the assertions that answer the question -------------------------
  assert.equal(r2.outcome, 'complete');
  assert.equal(r2.chunksDone, n, 'all chunks done after resume');
  assert.equal(
    r2.chunksProcessedThisRun, n - half,
    `resume must touch only the ${n - half} failed chunks, touched ${r2.chunksProcessedThisRun}`
  );
  assert.ok(
    r2.chunksProcessedThisRun < r1.chunksTotal,
    'resume must be strictly cheaper than a full reprocess'
  );
  const reprocessedFirstHalf = a2.seen.filter(seq => seq < half);
  assert.equal(reprocessedFirstHalf.length, 0,
    'already-done chunks must not be sent to the model again');
});

test('idempotence — repeated runs cannot duplicate findings', async () => {
  const { p, docId } = setup();
  const ok = new FakeAnalyzer(() => false);

  await p.run(docId, ok);
  const after1 = p.findingCount(docId);

  // Force every chunk back to pending and run again: worst case for duplicates.
  p.db.prepare(`UPDATE chunks SET status = 'pending', attempts = 0 WHERE document_id = ?`)
    .run(docId);
  await p.run(docId, ok);
  const after2 = p.findingCount(docId);

  assert.equal(after2, after1, 'finding count must be identical after a full re-run');
});

test('poison chunk is retired after maxAttempts instead of looping forever', async () => {
  const { p, docId } = setup();
  const always = new FakeAnalyzer(c => c.seq === 3);

  await p.run(docId, always);
  await p.run(docId, always);
  await p.run(docId, always);
  const beforeExtra = always.calls;
  await p.run(docId, always);   // should not touch the dead chunk at all

  const row = p.db.prepare(
    'SELECT status, attempts FROM chunks WHERE document_id = ? AND seq = 3'
  ).get(docId) as { status: string; attempts: number };

  assert.equal(row.status, 'dead');
  assert.equal(row.attempts, 3, 'attempts must stop at maxAttempts');
  assert.equal(always.calls, beforeExtra, 'a dead chunk is never re-sent');
});

test('expired lease is reclaimed — crash recovery without manual intervention', async () => {
  const { p, docId } = setup();
  // Simulate a worker that died mid-chunk: status left at processing, lease past.
  p.db.prepare(
    `UPDATE chunks SET status = 'processing', leased_until = '2000-01-01T00:00:00.000Z'
      WHERE document_id = ? AND seq = 0`
  ).run(docId);

  const ok = new FakeAnalyzer(() => false);
  const r = await p.run(docId, ok);
  assert.ok(ok.seen.includes(0), 'orphaned chunk must be reclaimed');
  assert.equal(r.outcome, 'complete');
});

test('findings cite a real page and compliance score reflects severity', async () => {
  const { p, docId } = setup();
  await p.run(docId, new FakeAnalyzer(() => false));

  const bad = p.db.prepare(
    'SELECT COUNT(*) AS n FROM findings WHERE document_id = ? AND (page_ref < 1 OR page_ref > 150)'
  ).get(docId) as { n: number };
  assert.equal(bad.n, 0, 'every finding must cite a page inside the document');

  assert.ok(p.findingCount(docId) > 0);
  assert.ok(p.complianceScore(docId) < 100, 'open critical findings must lower the score');
});
