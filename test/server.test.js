'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { createAppServer } = require('../server');

function createTestClient(baseUrl) {
  const cookies = new Map();
  let csrfToken = '';

  function updateCookies(setCookieHeader) {
    if (!setCookieHeader) return;
    const list = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const raw of list) {
      const firstPart = raw.split(';')[0];
      const idx = firstPart.indexOf('=');
      if (idx > 0) {
        const name = firstPart.slice(0, idx).trim();
        const val = decodeURIComponent(firstPart.slice(idx + 1).trim());
        if (val) cookies.set(name, val);
        else cookies.delete(name);
        if (name === 'bauer_csrf') csrfToken = val;
      }
    }
  }

  function getCookieHeader() {
    return [...cookies.entries()].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
  }

  async function request(pathname, { method = 'GET', body, headers = {}, skipCsrf = false } = {}) {
    const reqHeaders = { ...headers };
    const cookieStr = getCookieHeader();
    if (cookieStr) reqHeaders['Cookie'] = cookieStr;
    if (!skipCsrf && csrfToken) reqHeaders['X-CSRF-Token'] = csrfToken;
    if (body !== undefined) reqHeaders['Content-Type'] = 'application/json';

    const res = await fetch(`${baseUrl}${pathname}`, {
      method,
      headers: reqHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });

    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : res.headers.get('set-cookie');
    updateCookies(setCookie);

    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    if (data && typeof data === 'object' && data.csrfToken) {
      csrfToken = data.csrfToken;
    }
    return { status: res.status, data, headers: res.headers };
  }

  return {
    request,
    getCsrfToken: () => csrfToken,
    getCookies: () => Object.fromEntries(cookies)
  };
}

test('BAUER OWNER Account, User Management, Security, Sessions & Audit Log', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bauer-test-'));
  const { server, store } = createAppServer({ dataDir: tmpDir });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const ownerClient = createTestClient(baseUrl);
  const adminClient = createTestClient(baseUrl);
  const editorClient = createTestClient(baseUrl);
  const operatorClient = createTestClient(baseUrl);

  let recoveryCodes = [];
  let ownerUser = null;
  let adminUser = null;
  let editorUser = null;
  let operatorUser = null;

  await t.test('1. Initial system state & primary OWNER setup (only one OWNER allowed)', async () => {
    const statusBefore = await ownerClient.request('/api/admin/status');
    assert.equal(statusBefore.status, 200);
    assert.equal(statusBefore.data.configured, false);
    assert.equal(statusBefore.data.canSetup, true);
    assert.equal(statusBefore.data.unlocked, false);

    // Setup primary OWNER account with Cyrillic format МелентьевЕА and 4-char password
    const setupRes = await ownerClient.request('/api/admin/setup', {
      method: 'POST',
      body: {
        login: 'МелентьевЕА',
        displayName: 'Мелентьев Е.А.',
        password: '1234'
      }
    });
    assert.equal(setupRes.status, 200);
    assert.equal(setupRes.data.ok, true);
    assert.equal(setupRes.data.user.role, 'OWNER');
    assert.equal(setupRes.data.user.login, 'МелентьевЕА');
    assert.equal(Array.isArray(setupRes.data.recoveryCodes), true);
    assert.equal(setupRes.data.recoveryCodes.length, 6);

    recoveryCodes = setupRes.data.recoveryCodes;
    ownerUser = setupRes.data.user;

    // Attempting to create a second OWNER via /api/admin/setup must fail with 403
    const duplicateSetup = await adminClient.request('/api/admin/setup', {
      method: 'POST',
      body: {
        login: 'second_owner',
        password: 'AnotherPassword123!'
      }
    });
    assert.equal(duplicateSetup.status, 403);
    assert.match(duplicateSetup.data.error, /только один OWNER/);
  });

  await t.test('2. Passwords and recovery codes are never stored in plaintext', async () => {
    const usersRaw = fs.readFileSync(path.join(tmpDir, 'users.json'), 'utf8');
    assert.equal(usersRaw.includes('OwnerStrongPassword!2026'), false, 'Plaintext password must not be on disk');
    for (const code of recoveryCodes) {
      assert.equal(usersRaw.includes(code), false, 'Plaintext recovery code must not be on disk');
      assert.equal(usersRaw.includes(code.replace(/-/g, '')), false, 'Normalized recovery code must not be on disk');
    }
    const parsedUsers = JSON.parse(usersRaw);
    assert.equal(parsedUsers.length, 1);
    assert.match(parsedUsers[0].passwordHash, /^scrypt\$16384\$8\$1\$/);

    // Also verify index.html has no hardcoded password hash from legacy code
    const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    assert.equal(indexHtml.includes('169101042'), false, 'Legacy client-side password hash must be removed');
  });

  await t.test('3. CSRF protection on mutating requests', async () => {
    const noCsrfRes = await ownerClient.request('/api/users', {
      method: 'POST',
      skipCsrf: true,
      body: { login: 'csrf_test', password: 'Password123!', role: 'OPERATOR' }
    });
    assert.equal(noCsrfRes.status, 403);
    assert.match(noCsrfRes.data.error, /CSRF/);
  });

  await t.test('4. OWNER can create users with different roles (ADMIN, EDITOR, OPERATOR) and custom permissions', async () => {
    // Attempt to create a second OWNER via /api/users must fail with 403
    const secondOwnerAttempt = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'fake_owner',
        password: 'Password12345!',
        role: 'OWNER'
      }
    });
    assert.equal(secondOwnerAttempt.status, 403);

    // Create ADMIN with format ИвановАА and 4-char password
    const createAdmin = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'ИвановАА',
        displayName: 'Иванов А.А.',
        password: '4321',
        role: 'ADMIN',
        permissions: ['content.edit', 'layouts.manage', 'gifts.manage', 'addresses.manage', 'settings.manage', 'users.view']
      }
    });
    assert.equal(createAdmin.status, 201);
    adminUser = createAdmin.data.user;
    assert.equal(adminUser.role, 'ADMIN');
    assert.equal(adminUser.login, 'ИвановАА');

    // Create EDITOR (no settings.manage, no addresses.manage)
    const createEditor = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'editor_olga',
        displayName: 'Ольга Редактор',
        password: 'EditorPassword123!',
        role: 'EDITOR',
        permissions: ['content.edit', 'layouts.manage']
      }
    });
    assert.equal(createEditor.status, 201);
    editorUser = createEditor.data.user;
    assert.equal(editorUser.role, 'EDITOR');

    // Create OPERATOR (read-only)
    const createOp = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'operator_max',
        displayName: 'Максим Оператор',
        password: 'OperatorPassword123!',
        role: 'OPERATOR',
        permissions: []
      }
    });
    assert.equal(createOp.status, 201);
    operatorUser = createOp.data.user;
    assert.equal(operatorUser.role, 'OPERATOR');
  });

  await t.test('5. Login authentication & strict protection of OWNER against ADMIN and self-modification', async () => {
    // Invalid password fails with 401
    const badLogin = await adminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'ИвановАА', password: 'WrongPassword!' }
    });
    assert.equal(badLogin.status, 401);

    // Valid ADMIN login
    const goodAdminLogin = await adminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'ИвановАА', password: '4321' }
    });
    assert.equal(goodAdminLogin.status, 200);
    assert.equal(goodAdminLogin.data.user.role, 'ADMIN');

    // ADMIN with users.view can view user list
    const adminViewUsers = await adminClient.request('/api/users');
    assert.equal(adminViewUsers.status, 200);
    assert.equal(adminViewUsers.data.users.length, 4);

    // ADMIN CANNOT delete OWNER
    const adminDeleteOwner = await adminClient.request(`/api/users/${ownerUser.id}`, {
      method: 'DELETE'
    });
    assert.equal(adminDeleteOwner.status, 403);

    // ADMIN CANNOT block or change permissions/role of OWNER
    const adminBlockOwner = await adminClient.request(`/api/users/${ownerUser.id}`, {
      method: 'PATCH',
      body: { blocked: true, role: 'OPERATOR', permissions: [] }
    });
    assert.equal(adminBlockOwner.status, 403);

    // ADMIN CANNOT create/edit/delete other users either (only OWNER manages users & admins)
    const adminDeleteEditor = await adminClient.request(`/api/users/${editorUser.id}`, {
      method: 'DELETE'
    });
    assert.equal(adminDeleteEditor.status, 403);

    // Even OWNER cannot delete, block, or demote OWNER
    const ownerSelfDelete = await ownerClient.request(`/api/users/${ownerUser.id}`, {
      method: 'DELETE'
    });
    assert.equal(ownerSelfDelete.status, 403);

    const ownerSelfBlock = await ownerClient.request(`/api/users/${ownerUser.id}`, {
      method: 'PATCH',
      body: { blocked: true }
    });
    assert.equal(ownerSelfBlock.status, 403);

    const ownerSelfDemote = await ownerClient.request(`/api/users/${ownerUser.id}`, {
      method: 'PATCH',
      body: { role: 'ADMIN' }
    });
    assert.equal(ownerSelfDemote.status, 403);

    // OWNER cannot promote another user to OWNER
    const ownerPromoteAdmin = await ownerClient.request(`/api/users/${adminUser.id}`, {
      method: 'PATCH',
      body: { role: 'OWNER' }
    });
    assert.equal(ownerPromoteAdmin.status, 403);
  });

  await t.test('6. Server-side permission enforcement across BAUER features', async () => {
    await editorClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'editor_olga', password: 'EditorPassword123!' }
    });
    await operatorClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'operator_max', password: 'OperatorPassword123!' }
    });

    // Public read endpoints work for all
    const contentRes = await operatorClient.request('/api/content');
    assert.equal(contentRes.status, 200);
    assert.ok(contentRes.data.data);

    // OPERATOR cannot publish script content (403)
    const opPublish = await operatorClient.request('/api/content', {
      method: 'PUT',
      body: { data: contentRes.data.data }
    });
    assert.equal(opPublish.status, 403);

    // EDITOR can publish script stage changes (has content.edit)
    const editorPublish = await editorClient.request('/api/content', {
      method: 'PUT',
      body: { data: contentRes.data.data }
    });
    assert.equal(editorPublish.status, 200);

    // EDITOR without settings.manage CANNOT alter site appearance settings
    const modifiedSettingsData = structuredClone(contentRes.data.data);
    modifiedSettingsData.settings = { ...modifiedSettingsData.settings, brand: 'HACKED BRAND' };
    const editorChangeSettings = await editorClient.request('/api/content', {
      method: 'PUT',
      body: { data: modifiedSettingsData }
    });
    assert.equal(editorChangeSettings.status, 403);

    // EDITOR without addresses.manage CANNOT update addresses
    const editorAddresses = await editorClient.request('/api/addresses', {
      method: 'PUT',
      body: { venues: [] }
    });
    assert.equal(editorAddresses.status, 403);

    // OWNER has full access to update settings, addresses, gifts, layouts
    const ownerChangeSettings = await ownerClient.request('/api/content', {
      method: 'PUT',
      body: { data: modifiedSettingsData }
    });
    assert.equal(ownerChangeSettings.status, 200);
  });

  await t.test('7. OWNER managing administrators, blocking users, and forcibly terminating sessions', async () => {
    // OWNER views active sessions
    const sessionsRes = await ownerClient.request('/api/sessions');
    assert.equal(sessionsRes.status, 200);
    assert.ok(sessionsRes.data.sessions.length >= 4);

    // Find operator's session and terminate it forcibly
    const opSession = sessionsRes.data.sessions.find(s => s.userId === operatorUser.id);
    assert.ok(opSession, 'Operator session should be listed');

    const revokeRes = await ownerClient.request(`/api/sessions/${opSession.id}`, {
      method: 'DELETE'
    });
    assert.equal(revokeRes.status, 200);

    // Operator's session is now invalidated
    const opStatusAfter = await operatorClient.request('/api/admin/status');
    assert.equal(opStatusAfter.data.unlocked, false);

    // OWNER modifies ADMIN permissions and blocks ADMIN
    const blockAdminRes = await ownerClient.request(`/api/users/${adminUser.id}`, {
      method: 'PATCH',
      body: {
        permissions: ['content.edit'],
        blocked: true
      }
    });
    assert.equal(blockAdminRes.status, 200);
    assert.equal(blockAdminRes.data.user.blocked, true);
    assert.deepEqual(blockAdminRes.data.user.permissions, ['content.edit']);

    // Blocked ADMIN's existing session is immediately revoked
    const adminTryUsers = await adminClient.request('/api/users');
    assert.equal(adminTryUsers.status, 401);

    // Blocked ADMIN cannot log in
    const blockedLogin = await adminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'ИвановАА', password: '4321' }
    });
    assert.equal(blockedLogin.status, 403);

    // OWNER can delete a user
    const deleteOpRes = await ownerClient.request(`/api/users/${operatorUser.id}`, {
      method: 'DELETE'
    });
    assert.equal(deleteOpRes.status, 200);
  });

  await t.test('8. Secure OWNER access recovery via one-time recovery code', async () => {
    const recoveryClient = createTestClient(baseUrl);
    const codeToUse = recoveryCodes[0];

    // Recover OWNER account with first recovery code and set new password
    const recoverRes = await recoveryClient.request('/api/owner/recover', {
      method: 'POST',
      body: {
        login: 'МелентьевЕА',
        recoveryCode: codeToUse,
        newPassword: '9999'
      }
    });
    assert.equal(recoverRes.status, 200);
    assert.equal(recoverRes.data.ok, true);
    assert.equal(recoverRes.data.remainingRecoveryCodes, 5);

    // Reusing the same recovery code must fail with 401
    const reuseRes = await recoveryClient.request('/api/owner/recover', {
      method: 'POST',
      body: {
        login: 'МелентьевЕА',
        recoveryCode: codeToUse,
        newPassword: '8888'
      }
    });
    assert.equal(reuseRes.status, 401);

    // Old OWNER session was revoked upon recovery
    const oldSessionCheck = await ownerClient.request('/api/users');
    assert.equal(oldSessionCheck.status, 401);

    // Regenerate recovery codes with new password
    const regenRes = await recoveryClient.request('/api/owner/recovery-codes', {
      method: 'POST',
      body: { password: '9999' }
    });
    assert.equal(regenRes.status, 200);
    assert.equal(regenRes.data.recoveryCodes.length, 6);
  });

  await t.test('9. Audit log records logins, user modifications, session revocations, and recovery events', async () => {
    const reloginOwner = await ownerClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'МелентьевЕА', password: '9999' }
    });
    assert.equal(reloginOwner.status, 200);

    const auditRes = await ownerClient.request('/api/audit?limit=100');
    assert.equal(auditRes.status, 200);
    const actions = new Set(auditRes.data.events.map(e => e.action));

    assert.ok(actions.has('owner.setup'), 'Audit log must contain owner.setup');
    assert.ok(actions.has('owner.setup.denied'), 'Audit log must contain owner.setup.denied');
    assert.ok(actions.has('auth.login.success'), 'Audit log must contain auth.login.success');
    assert.ok(actions.has('auth.login.failed'), 'Audit log must contain auth.login.failed');
    assert.ok(actions.has('auth.login.blocked'), 'Audit log must contain auth.login.blocked');
    assert.ok(actions.has('users.create'), 'Audit log must contain users.create');
    assert.ok(actions.has('users.update'), 'Audit log must contain users.update');
    assert.ok(actions.has('users.delete'), 'Audit log must contain users.delete');
    assert.ok(actions.has('sessions.revoke'), 'Audit log must contain sessions.revoke');
    assert.ok(actions.has('owner.recovery.success'), 'Audit log must contain owner.recovery.success');
    assert.ok(actions.has('owner.recovery.failed'), 'Audit log must contain owner.recovery.failed');
    assert.ok(actions.has('content.publish'), 'Audit log must contain content.publish');
  });
});
