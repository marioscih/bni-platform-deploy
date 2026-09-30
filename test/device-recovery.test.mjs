import test from 'node:test';
import assert from 'node:assert/strict';
import { createPlatform } from '../src/platform.mjs';
import { createPlatformHttpServer } from '../src/http-server.mjs';
import { generateDevelopmentDeviceKeyPair } from '../src/identity-access/identity-service.mjs';

function fixture() {
  let time = Date.parse('2026-09-30T12:00:00Z');
  const p = createPlatform({ tokenSigningKey: Buffer.alloc(32, 7), activationPepper: 'recovery-test-pepper', now: () => new Date(time) });
  return { p, advance: n => { time += n; } };
}
const recovery = { customerReference: 'customer_recovery', activationCode: 'RECOVERY-SECRET-2026', recoveryReference: 'recovery_test_001', ttlSeconds: 60 };
async function setup(p) {
  await p.identity.bootstrapCustomer({ customerReference: recovery.customerReference, activationCode: 'ORIGINAL-SECRET-2026' });
  await p.ledger.createAccount({ accountReference: 'account_recovery', ownerReference: recovery.customerReference, displayName: 'Existing account', type: 'CUSTOMER' });
}
async function start(p, key, deviceReference = 'device_recovery', activationCode = recovery.activationCode) {
  return p.identity.beginEnrollment({ customerReference: recovery.customerReference, activationCode, deviceReference, publicKeySpki: key.publicKeySpki });
}
async function complete(p, key, challenge, appInstanceReference = 'instance_recovery') {
  return p.identity.completeEnrollment({ challengeId: challenge.challengeId, signature: key.sign(challenge.material), appInstanceReference });
}

test('recovery preserves ledger and permits a signed fresh device after consumed activation', async () => {
  const { p } = fixture(); await setup(p); const oldKey = generateDevelopmentDeviceKeyPair();
  await complete(p, oldKey, await start(p, oldKey, 'device_original', 'ORIGINAL-SECRET-2026'));
  const accounts = p.repository.snapshot().accounts; const journals = p.repository.snapshot().journals;
  await p.identity.issueDeviceRecovery(recovery);
  const key = generateDevelopmentDeviceKeyPair(); await complete(p, key, await start(p, key));
  assert.equal(p.repository.snapshot().devices.device_recovery.status, 'ACTIVE');
  assert.deepEqual(p.repository.snapshot().accounts, accounts); assert.deepEqual(p.repository.snapshot().journals, journals);
  await assert.rejects(() => start(p, key, 'device_replay'), /ENROLLMENT_DENIED/);
});

test('expiry blocks both issuance of enrollment challenge and completion', async () => {
  const { p, advance } = fixture(); await setup(p); await p.identity.issueDeviceRecovery(recovery);
  const key = generateDevelopmentDeviceKeyPair(); const challenge = await start(p, key); advance(60_000);
  await assert.rejects(() => start(p, key, 'device_second'), /ENROLLMENT_DENIED/);
  await assert.rejects(() => complete(p, key, challenge), /ENROLLMENT_DENIED/);
});

test('two outstanding challenges cannot consume one activation twice', async () => {
  const { p } = fixture(); await setup(p); await p.identity.issueDeviceRecovery(recovery);
  const a = generateDevelopmentDeviceKeyPair(), b = generateDevelopmentDeviceKeyPair();
  const one = await start(p, a, 'device_first'), two = await start(p, b, 'device_second');
  await complete(p, a, one);
  await assert.rejects(() => complete(p, b, two), /ENROLLMENT_DENIED/);
  assert.equal(p.repository.snapshot().devices.device_second, undefined);
});

test('rotating recovery invalidates old code and pending challenges', async () => {
  const { p } = fixture(); await setup(p); const key = generateDevelopmentDeviceKeyPair();
  const previous = await start(p, key, 'device_original', 'ORIGINAL-SECRET-2026');
  await p.identity.issueDeviceRecovery(recovery);
  await assert.rejects(() => complete(p, key, previous), /CHALLENGE_INVALID_OR_REPLAYED/);
  await assert.rejects(() => start(p, key, 'device_old_code', 'ORIGINAL-SECRET-2026'), /ENROLLMENT_DENIED/);
});

test('idempotent reissue never reopens a consumed code and conflicting retries fail', async () => {
  const { p } = fixture(); await setup(p);
  const first = await p.identity.issueDeviceRecovery(recovery);
  const key = generateDevelopmentDeviceKeyPair(); await complete(p, key, await start(p, key));
  assert.deepEqual(await p.identity.issueDeviceRecovery(recovery), first);
  await assert.rejects(() => start(p, key, 'device_replay'), /ENROLLMENT_DENIED/);
  await assert.rejects(() => p.identity.issueDeviceRecovery({ ...recovery, activationCode: 'DIFFERENT-SECRET-2026' }), /IDEMPOTENCY_CONFLICT/);
});

test('invalid TTL and inactive or absent customers cannot obtain recovery', async () => {
  const { p } = fixture();
  await assert.rejects(() => p.identity.issueDeviceRecovery(recovery), /CUSTOMER_NOT_ACTIVE/);
  await setup(p); await assert.rejects(() => p.identity.issueDeviceRecovery({ ...recovery, ttlSeconds: 901 }), /INVALID_RECOVERY_TTL/);
  await p.repository.transaction(state => { state.customers.customer_recovery.status = 'SUSPENDED'; });
  await assert.rejects(() => p.identity.issueDeviceRecovery(recovery), /CUSTOMER_NOT_ACTIVE/);
});

test('recovery HTTP requires admin and restricted token cannot access other admin actions', async () => {
  const { p } = fixture(); await setup(p);
  const server = createPlatformHttpServer(p, { recoveryAdminToken: 'restricted-recovery-secret', adminToken: 'full-admin-secret', requireTlsForwarding: false });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const request = async (path, token) => fetch(origin + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { 'x-bni-admin-token': token } : {}) }, body: JSON.stringify(recovery) });
    assert.equal((await request('/v2/admin/device-recovery')).status, 403);
    const ok = await request('/v2/admin/device-recovery', 'restricted-recovery-secret'); assert.equal(ok.status, 200);
    assert.equal(JSON.stringify(await ok.json()).includes(recovery.activationCode), false);
    assert.equal((await request('/v2/admin/customers', 'restricted-recovery-secret')).status, 403);
    assert.equal((await fetch(origin + '/v2/admin/backup', { headers: { 'x-bni-admin-token': 'restricted-recovery-secret' } })).status, 403);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
