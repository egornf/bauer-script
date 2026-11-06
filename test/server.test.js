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
  const { server, store } = createAppServer({ dataDir: tmpDir, seedDefaultOwner: false });

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
        mustChangePassword: false,
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
        mustChangePassword: false,
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
        mustChangePassword: false,
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

  await t.test('10. ADMIN full access, HEAD (Руководитель отдела) script creation without deletion, and OPERATOR (Менеджер обзвона) department hierarchy', async () => {
    const fullAdminClient = createTestClient(baseUrl);
    const headClient = createTestClient(baseUrl);
    const mgrClient = createTestClient(baseUrl);

    // 1. OWNER creates a full ADMIN with default permissions (all permissions)
    const createFullAdmin = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'admin_full',
        displayName: 'Главный Администратор',
        password: 'AdminPass123',
        role: 'ADMIN',
        mustChangePassword: false
      }
    });
    assert.equal(createFullAdmin.status, 201);
    assert.ok(createFullAdmin.data.user.permissions.includes('users.manage'));
    assert.ok(createFullAdmin.data.user.permissions.includes('layouts.delete'));

    await fullAdminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'admin_full', password: 'AdminPass123' }
    });

    // 2. ADMIN creates a HEAD (Руководитель отдела)
    const createHead = await fullAdminClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'head_sergey',
        displayName: 'Сергей Руководитель',
        password: 'HeadPass123',
        role: 'HEAD',
        mustChangePassword: false
      }
    });
    assert.equal(createHead.status, 201);
    const headUser = createHead.data.user;
    assert.equal(headUser.role, 'HEAD');
    assert.ok(headUser.permissions.includes('content.edit'));
    assert.ok(headUser.permissions.includes('layouts.manage'));
    assert.ok(!headUser.permissions.includes('layouts.delete'));

    // 3. ADMIN creates a Менеджер обзвона (OPERATOR) assigned to head_sergey
    const createAssignedOp = await fullAdminClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'mgr_anna',
        displayName: 'Анна Менеджер обзвона',
        password: 'MgrPass123',
        role: 'OPERATOR',
        managerId: headUser.id,
        mustChangePassword: false
      }
    });
    assert.equal(createAssignedOp.status, 201);
    assert.equal(createAssignedOp.data.user.managerId, headUser.id);

    // 4. HEAD logs in and adds their own Менеджер обзвона
    await headClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'head_sergey', password: 'HeadPass123' }
    });

    const headCreateOp = await headClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'mgr_dmitry',
        displayName: 'Дмитрий Менеджер',
        password: 'MgrPass456',
        role: 'OPERATOR',
        mustChangePassword: false
      }
    });
    assert.equal(headCreateOp.status, 201);
    const dmitryUser = headCreateOp.data.user;
    assert.equal(dmitryUser.role, 'OPERATOR');
    assert.equal(dmitryUser.managerId, headUser.id);

    // HEAD cannot create an ADMIN or EDITOR
    const headCreateAdmin = await headClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'illegal_admin',
        password: 'Password123',
        role: 'ADMIN'
      }
    });
    assert.equal(headCreateAdmin.status, 403);

    // HEAD can block/unblock their own manager, but CANNOT delete them
    const headBlockMgr = await headClient.request(`/api/users/${dmitryUser.id}`, {
      method: 'PATCH',
      body: { blocked: true }
    });
    assert.equal(headBlockMgr.status, 200);
    assert.equal(headBlockMgr.data.user.blocked, true);

    const headDeleteMgr = await headClient.request(`/api/users/${dmitryUser.id}`, {
      method: 'DELETE'
    });
    assert.equal(headDeleteMgr.status, 403);

    // 5. HEAD can create/save a script layout, but CANNOT delete any layout
    const contentRes = await headClient.request('/api/content');
    const createLayoutRes = await headClient.request('/api/layouts', {
      method: 'POST',
      body: {
        name: 'Скрипт отдела Сергея',
        data: contentRes.data.data
      }
    });
    assert.equal(createLayoutRes.status, 200);
    const newLayoutId = createLayoutRes.data.layout.id;

    const headDeleteLayout = await headClient.request(`/api/layouts/${newLayoutId}`, {
      method: 'DELETE'
    });
    assert.equal(headDeleteLayout.status, 403);

    // Full ADMIN CAN delete the layout
    const adminDeleteLayout = await fullAdminClient.request(`/api/layouts/${newLayoutId}`, {
      method: 'DELETE'
    });
    assert.equal(adminDeleteLayout.status, 200);
  });

  await t.test('11. Department scripts selection: HEAD and OWNER can choose scripts for their department; empty selection shows all scripts', async () => {
    const headClient = createTestClient(baseUrl);
    const mgrClient = createTestClient(baseUrl);
    const ownerMgrClient = createTestClient(baseUrl);

    await headClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'head_sergey', password: 'HeadPass123' }
    });

    // Create operator under head_sergey
    const opRes = await headClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'op_dept_test',
        password: 'Pass1234!',
        role: 'OPERATOR',
        mustChangePassword: false
      }
    });
    assert.equal(opRes.status, 201);
    const opUser = opRes.data.user;

    await mgrClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'op_dept_test', password: 'Pass1234!' }
    });

    // 1. Initially nothing is selected for head_sergey: operator sees all scripts
    const initialScripts = await mgrClient.request('/api/scripts');
    assert.equal(initialScripts.status, 200);
    assert.ok(initialScripts.data.layouts.length >= 2);
    const totalScriptsCount = initialScripts.data.allLayouts.length;

    // 2. HEAD chooses only the first script for their department
    const targetScriptId = initialScripts.data.allLayouts[0].id;
    const saveDeptRes = await headClient.request('/api/department/scripts', {
      method: 'PUT',
      body: { scriptIds: [targetScriptId] }
    });
    assert.equal(saveDeptRes.status, 200);
    assert.deepEqual(saveDeptRes.data.scriptIds, [targetScriptId]);

    // Operator in this department now sees only this 1 selected script
    const filteredScripts = await mgrClient.request('/api/scripts');
    assert.equal(filteredScripts.status, 200);
    assert.equal(filteredScripts.data.layouts.length, 1);
    assert.equal(filteredScripts.data.layouts[0].id, targetScriptId);

    // 3. OWNER is also a department head: create an operator assigned to OWNER
    const ownerCreateOp = await ownerClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'op_owner_dept',
        password: 'PassOwner123!',
        role: 'OPERATOR',
        managerId: ownerUser.id,
        mustChangePassword: false
      }
    });
    assert.equal(ownerCreateOp.status, 201);
    assert.equal(ownerCreateOp.data.user.managerId, ownerUser.id);

    await ownerMgrClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'op_owner_dept', password: 'PassOwner123!' }
    });

    // OWNER has not selected department scripts yet: operator sees all scripts
    const ownerOpScripts = await ownerMgrClient.request('/api/scripts');
    assert.equal(ownerOpScripts.status, 200);
    assert.equal(ownerOpScripts.data.layouts.length, totalScriptsCount);

    // 4. Reset HEAD's department scripts to empty array: operator again sees all scripts
    const resetDeptRes = await headClient.request('/api/department/scripts', {
      method: 'PUT',
      body: { scriptIds: [] }
    });
    assert.equal(resetDeptRes.status, 200);

    const afterResetScripts = await mgrClient.request('/api/scripts');
    assert.equal(afterResetScripts.status, 200);
    assert.equal(afterResetScripts.data.layouts.length, totalScriptsCount);
  });

  await t.test('12. OPERATOR permissions: can edit site styling, fonts, and block colors, but STRICTLY forbidden from modifying text', async () => {
    const mgrClient = createTestClient(baseUrl);
    await mgrClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'op_dept_test', password: 'Pass1234!' }
    });

    const contentRes = await mgrClient.request('/api/content');
    assert.equal(contentRes.status, 200);
    const originalContent = contentRes.data.data;

    // 1. Operator updates styling: fontSize, accent color, and blockBg in lineFormats
    const styledContent = structuredClone(originalContent);
    styledContent.settings.fontSize = 24;
    styledContent.settings.accent = '#2166cc';
    if (styledContent.stages[0]) {
      styledContent.stages[0].lineFormats = styledContent.stages[0].lineFormats || [];
      styledContent.stages[0].lineFormats[0] = { style: { blockBg: '#daf5e4' }, ranges: [] };
    }

    const saveStylingRes = await mgrClient.request('/api/content', {
      method: 'PUT',
      body: { data: styledContent }
    });
    assert.equal(saveStylingRes.status, 200);

    // 2. Operator attempts to alter text in lines: MUST fail with 403
    const textHackedContent = structuredClone(styledContent);
    textHackedContent.stages[0].lines[0] = 'HACKED TEXT BY OPERATOR';

    const hackTextRes = await mgrClient.request('/api/content', {
      method: 'PUT',
      body: { data: textHackedContent }
    });
    assert.equal(hackTextRes.status, 403);
    assert.match(hackTextRes.data.error, /не имеет права менять текст/);

    // 3. Operator attempts to alter stage title: MUST fail with 403
    const titleHackedContent = structuredClone(styledContent);
    titleHackedContent.stages[0].title = 'HACKED STAGE TITLE';

    const hackTitleRes = await mgrClient.request('/api/content', {
      method: 'PUT',
      body: { data: titleHackedContent }
    });
    assert.equal(hackTitleRes.status, 403);
    assert.match(hackTitleRes.data.error, /не имеет права менять текст/);

    // 4. Operator cannot delete layout
    const deleteLayoutRes = await mgrClient.request('/api/layouts/any_id', {
      method: 'DELETE'
    });
    assert.equal(deleteLayoutRes.status, 403);
  });

  await t.test('13. Temporary passwords: created/reset users receive temporary passwords and MUST change them upon first login', async () => {
    const adminClient = createTestClient(baseUrl);
    await adminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'admin_full', password: 'AdminPass123' }
    });

    // 1. Admin creates a user with temporary password (default behavior when mustChangePassword is not specified)
    const createRes = await adminClient.request('/api/users', {
      method: 'POST',
      body: {
        login: 'temp_user_test',
        displayName: 'Сотрудник с временным паролем',
        role: 'OPERATOR',
        password: 'InitialTempPass123!'
      }
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.data.user.mustChangePassword, true);
    const userId = createRes.data.user.id;

    // 2. User logs in with temporary password
    const userClient = createTestClient(baseUrl);
    const loginRes = await userClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'temp_user_test', password: 'InitialTempPass123!' }
    });
    assert.equal(loginRes.status, 200);
    assert.equal(loginRes.data.user.mustChangePassword, true);

    // 3. User cannot perform mutating operations before changing password
    const blockMutatingRes = await userClient.request('/api/content', {
      method: 'PUT',
      body: { data: {} }
    });
    assert.equal(blockMutatingRes.status, 403);
    assert.equal(blockMutatingRes.data.mustChangePassword, true);

    // 4. User changes temporary password to their own permanent password
    const changeRes = await userClient.request('/api/auth/change-password', {
      method: 'POST',
      body: { newPassword: 'MyNewPermanentPass123!' }
    });
    assert.equal(changeRes.status, 200);
    assert.equal(changeRes.data.ok, true);
    assert.equal(changeRes.data.user.mustChangePassword, false);

    // 5. Logout and verify old temporary password no longer works
    await userClient.request('/api/admin/logout', { method: 'POST', body: {} });
    const oldLoginRes = await userClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'temp_user_test', password: 'InitialTempPass123!' }
    });
    assert.equal(oldLoginRes.status, 401);

    // 6. Login with new permanent password succeeds and mustChangePassword is false
    const newLoginRes = await userClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'temp_user_test', password: 'MyNewPermanentPass123!' }
    });
    assert.equal(newLoginRes.status, 200);
    assert.equal(newLoginRes.data.user.mustChangePassword, false);

    // 7. Admin resets password for user -> mustChangePassword is reset to true
    const resetRes = await adminClient.request(`/api/users/${userId}`, {
      method: 'PATCH',
      body: { password: 'SecondTempPass123!' }
    });
    assert.equal(resetRes.status, 200);
    assert.equal(resetRes.data.user.mustChangePassword, true);
  });

  await t.test('14. ADMIN can switch departments and manage department scripts per HEAD, which correctly filter for assigned OPERATORs', async () => {
    // 1. Admin login
    const adminClient = createTestClient(baseUrl);
    const loginRes = await adminClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'admin_full', password: 'AdminPass123' }
    });
    assert.equal(loginRes.status, 200);

    // 2. Head (head_sergey) and Operator (op_dept_test) created in previous tests
    // Check all available layouts
    const allScriptsRes = await adminClient.request('/api/scripts');
    assert.equal(allScriptsRes.status, 200);
    const layouts = allScriptsRes.data.allLayouts;
    assert.ok(layouts.length >= 2, 'Need at least 2 layouts for department testing');
    const targetScript1 = layouts[0].id;
    const targetScript2 = layouts[1].id;

    // Get list of users to find head_sergey and owner
    const usersRes = await adminClient.request('/api/users');
    assert.equal(usersRes.status, 200);
    const headSergey = usersRes.data.users.find(u => u.login === 'head_sergey');
    const ownerUser = usersRes.data.users.find(u => u.role === 'OWNER');
    assert.ok(headSergey, 'head_sergey must exist');
    assert.ok(ownerUser, 'owner must exist');

    // 3. Admin calls GET /api/department/scripts without headId -> defaults cleanly without error
    const defaultDeptRes = await adminClient.request('/api/department/scripts');
    assert.equal(defaultDeptRes.status, 200);
    assert.ok(Array.isArray(defaultDeptRes.data.scriptIds));
    assert.ok(Array.isArray(defaultDeptRes.data.layouts));

    // 4. Admin queries specifically for head_sergey
    const headDeptRes = await adminClient.request(`/api/department/scripts?headId=${headSergey.id}`);
    assert.equal(headDeptRes.status, 200);
    assert.equal(headDeptRes.data.headId, headSergey.id);
    assert.equal(headDeptRes.data.headLogin, 'head_sergey');

    // 5. Operator (op_dept_test) assigned to head_sergey logs in
    const opClient = createTestClient(baseUrl);
    await opClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'op_dept_test', password: 'Pass1234!' }
    });

    // 6. Admin assigns script1 and script2 to head_sergey's department
    const saveRes = await adminClient.request('/api/department/scripts', {
      method: 'PUT',
      body: {
        headId: headSergey.id,
        scriptIds: [targetScript1, targetScript2]
      }
    });
    assert.equal(saveRes.status, 200);
    assert.equal(saveRes.data.headId, headSergey.id);
    assert.deepEqual(saveRes.data.scriptIds.sort(), [targetScript1, targetScript2].sort());

    // 7. Verify switching departments:
    // When Admin asks for head_sergey, returns the 2 scripts
    const verifyHeadDept = await adminClient.request(`/api/department/scripts?headId=${headSergey.id}`);
    assert.equal(verifyHeadDept.status, 200);
    assert.deepEqual(verifyHeadDept.data.scriptIds.sort(), [targetScript1, targetScript2].sort());

    // When Admin switches to owner's department, returns owner's scripts (which is currently empty or different)
    const verifyOwnerDept = await adminClient.request(`/api/department/scripts?headId=${ownerUser.id}`);
    assert.equal(verifyOwnerDept.status, 200);
    assert.equal(verifyOwnerDept.data.headId, ownerUser.id);
    assert.notDeepEqual(verifyOwnerDept.data.scriptIds.sort(), [targetScript1, targetScript2].sort());

    // 8. Operator under head_sergey MUST see exactly the 2 department scripts in /api/scripts
    const opScriptsRes = await opClient.request('/api/scripts');
    assert.equal(opScriptsRes.status, 200);
    assert.equal(opScriptsRes.data.layouts.length, 2);
    const opLayoutIds = opScriptsRes.data.layouts.map(l => l.id).sort();
    assert.deepEqual(opLayoutIds, [targetScript1, targetScript2].sort());

    // 9. Operator under Owner (op_owner_dept) should NOT be affected by head_sergey's scripts
    const opOwnerClient = createTestClient(baseUrl);
    await opOwnerClient.request('/api/admin/login', {
      method: 'POST',
      body: { login: 'op_owner_dept', password: 'PassOwner123!' }
    });
    const opOwnerScriptsRes = await opOwnerClient.request('/api/scripts');
    assert.equal(opOwnerScriptsRes.status, 200);
    assert.equal(opOwnerScriptsRes.data.layouts.length, layouts.length);

    // 10. Admin resets head_sergey's department scripts
    const resetRes = await adminClient.request('/api/department/scripts', {
      method: 'PUT',
      body: { headId: headSergey.id, scriptIds: [] }
    });
    assert.equal(resetRes.status, 200);
    assert.deepEqual(resetRes.data.scriptIds, []);

    // Operator under head_sergey now sees all layouts again
    const opResetScripts = await opClient.request('/api/scripts');
    assert.equal(opResetScripts.status, 200);
    assert.equal(opResetScripts.data.layouts.length, layouts.length);
  });

  await t.test('15. Theme preferences persistence on every account type (OWNER, ADMIN, HEAD, EDITOR, OPERATOR) and transferring/sharing themes between employees', async () => {
    // Clients for each role
    const owner = createTestClient(baseUrl);
    const ownerLoginRes = await owner.request('/api/admin/login', { method: 'POST', body: { login: ownerUser.login, password: '9999' } });
    assert.equal(ownerLoginRes.status, 200, 'Owner login should succeed with password 9999');

    const admin = createTestClient(baseUrl);
    await admin.request('/api/admin/login', { method: 'POST', body: { login: 'admin_full', password: 'AdminPass123' } });

    const head = createTestClient(baseUrl);
    await head.request('/api/admin/login', { method: 'POST', body: { login: 'head_sergey', password: 'HeadPass123' } });

    const editor = createTestClient(baseUrl);
    await editor.request('/api/admin/login', { method: 'POST', body: { login: 'editor_olga', password: 'EditorPassword123!' } });

    const op1 = createTestClient(baseUrl);
    await op1.request('/api/admin/login', { method: 'POST', body: { login: 'op_dept_test', password: 'Pass1234!' } });

    const op2 = createTestClient(baseUrl);
    await op2.request('/api/admin/login', { method: 'POST', body: { login: 'op_owner_dept', password: 'PassOwner123!' } });

    // Retrieve user profiles
    const usersRes = await admin.request('/api/users');
    const uOp1 = usersRes.data.users.find(u => u.login === 'op_dept_test');
    const uOp2 = usersRes.data.users.find(u => u.login === 'op_owner_dept');
    const uHead = usersRes.data.users.find(u => u.login === 'head_sergey');

    // --- 1. Test Saving Themes on EVERY account type ---
    const rolesToTest = [
      { name: 'OWNER', client: owner, color: '#102f44' },
      { name: 'ADMIN', client: admin, color: '#0d3832' },
      { name: 'HEAD', client: head, color: '#0d0221' },
      { name: 'EDITOR', client: editor, color: '#2a1a08' },
      { name: 'OPERATOR', client: op1, color: '#070b18' }
    ];

    for (const r of rolesToTest) {
      const myTheme = {
        name: `Тема для ${r.name}`,
        headerBg: r.color,
        theme: 'dark',
        accent: '#00f5d4',
        cardStyle: 'glass',
        updatedAt: Date.now()
      };
      const myCustomThemes = [
        { id: `custom_${r.name.toLowerCase()}`, name: `Кастом ${r.name}`, headerBg: r.color, theme: 'dark' }
      ];

      // POST /api/user/preferences
      const postPref = await r.client.request('/api/user/preferences', {
        method: 'POST',
        body: { theme: myTheme, customThemes: myCustomThemes }
      });
      assert.equal(postPref.status, 200, `POST /api/user/preferences should succeed for ${r.name}`);
      assert.equal(postPref.data.theme.headerBg, r.color);
      assert.equal(postPref.data.customThemes.length, 1);

      // GET /api/user/preferences
      const getPref = await r.client.request('/api/user/preferences');
      assert.equal(getPref.status, 200, `GET /api/user/preferences should succeed for ${r.name}`);
      assert.equal(getPref.data.theme.name, `Тема для ${r.name}`);
      assert.equal(getPref.data.customThemes[0].id, `custom_${r.name.toLowerCase()}`);

      // GET /api/admin/status (verifying user.theme and user.customThemes survive sanitizeUser across devices)
      const getStatus = await r.client.request('/api/admin/status');
      assert.equal(getStatus.status, 200);
      assert.ok(getStatus.data.user, `User must be present in status for ${r.name}`);
      assert.equal(getStatus.data.user.theme?.headerBg, r.color, `theme must be returned in status for ${r.name}`);
      assert.equal(getStatus.data.user.customThemes?.length, 1, `customThemes must be returned in status for ${r.name}`);
    }

    // --- 2. Test Transferring / Sharing theme directly between employees ---
    // op1 (op_dept_test) shares a theme directly with op2 (op_owner_dept)
    const directThemePayload = {
      theme: {
        name: 'Супер-Неон от Оператора 1',
        desc: 'Специальная тема',
        headerBg: '#051923',
        theme: 'dark',
        accent: '#00f5d4',
        cardStyle: 'neon'
      },
      targetUserId: uOp2.id,
      targetUserName: 'Оператор 2'
    };
    const shareDirectRes = await op1.request('/api/themes/shared', {
      method: 'POST',
      body: directThemePayload
    });
    assert.equal(shareDirectRes.status, 201);
    const sharedThemeId = shareDirectRes.data.theme.id;
    assert.ok(sharedThemeId);

    // op2 (target recipient) should see it
    const op2SharedRes = await op2.request('/api/themes/shared');
    assert.equal(op2SharedRes.status, 200);
    const receivedDirect = op2SharedRes.data.sharedThemes.find(t => t.id === sharedThemeId);
    assert.ok(receivedDirect, 'Target recipient (op2) must receive the shared theme');
    assert.equal(receivedDirect.name, 'Супер-Неон от Оператора 1');

    // head (not the target, and different user) should NOT see this direct 1-on-1 theme
    const headSharedRes = await head.request('/api/themes/shared');
    assert.equal(headSharedRes.status, 200);
    const headSeesDirect = headSharedRes.data.sharedThemes.find(t => t.id === sharedThemeId);
    assert.strictEqual(headSeesDirect, undefined, 'Head must not see a private theme directed to another user');

    // --- 3. Test Department Theme Sharing (HEAD shares with department) ---
    const deptThemePayload = {
      theme: {
        name: 'Корпоративная тема Отдела Сергея',
        headerBg: '#1e3a8a',
        theme: 'dark',
        accent: '#3b82f6'
      },
      shareAll: true
    };
    const headShareRes = await head.request('/api/themes/shared', {
      method: 'POST',
      body: deptThemePayload
    });
    assert.equal(headShareRes.status, 201);
    const headThemeId = headShareRes.data.theme.id;

    // op1 (assigned to head_sergey) MUST see the department theme
    const op1AfterHeadShare = await op1.request('/api/themes/shared');
    assert.ok(op1AfterHeadShare.data.sharedThemes.some(t => t.id === headThemeId), 'Operator in department must see head shareAll theme');

    // op2 (assigned to owner, not head_sergey) must NOT see head_sergey department theme
    const op2AfterHeadShare = await op2.request('/api/themes/shared');
    assert.ok(!op2AfterHeadShare.data.sharedThemes.some(t => t.id === headThemeId), 'Operator in another department must not see head_sergey theme');

    // --- 4. Test Global Theme Sharing (OWNER shares with all) ---
    const globalThemePayload = {
      theme: {
        name: 'Глобальная тема Владельца',
        headerBg: '#042f2e',
        theme: 'dark',
        accent: '#14b8a6'
      },
      shareAll: true
    };
    const ownerShareRes = await owner.request('/api/themes/shared', {
      method: 'POST',
      body: globalThemePayload
    });
    assert.equal(ownerShareRes.status, 201);
    const globalThemeId = ownerShareRes.data.theme.id;

    // Everyone across the company should receive the owner's global theme
    for (const cl of [admin, head, editor, op1, op2]) {
      const listRes = await cl.request('/api/themes/shared');
      assert.ok(listRes.data.sharedThemes.some(t => t.id === globalThemeId), 'All roles must receive owner shareAll theme');
    }

    // --- 5. Test Deleting Shared Themes ---
    // op2 deletes the direct theme sent to them
    const deleteRes = await op2.request(`/api/themes/shared?id=${sharedThemeId}`, { method: 'DELETE' });
    assert.equal(deleteRes.status, 200);

    const op2AfterDelete = await op2.request('/api/themes/shared');
    assert.strictEqual(op2AfterDelete.data.sharedThemes.find(t => t.id === sharedThemeId), undefined, 'Theme must be removed after deletion');
  });

  await t.test('16. Whole script view (Весь скрипт) contains quick navigation side panel with jump items to all active stages', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const html = fs.readFileSync(path.resolve('index.html'), 'utf8');

    // Verify side navigation structure & classes
    assert.ok(html.includes('.whole-body-layout'), 'Must have .whole-body-layout');
    assert.ok(html.includes('.whole-sidebar'), 'Must have .whole-sidebar');
    assert.ok(html.includes('.whole-nav-item'), 'Must have .whole-nav-item');
    assert.ok(html.includes('.whole-nav-num'), 'Must have .whole-nav-num');
    assert.ok(html.includes('.whole-nav-text'), 'Must have .whole-nav-text');

    // Verify quick transitions click handler and scroll tracking
    assert.ok(html.includes('data-stage-index'), 'Stages must have data-stage-index');
    assert.ok(html.includes('scrollIntoView'), 'Must support smooth scroll transitions');

    // Verify dynamic objections block in left sidebar
    assert.ok(html.includes('whole-sidebar-ob-section'), 'Must have objections section in whole sidebar');
    assert.ok(html.includes('whole-ob-list'), 'Must have whole-ob-list');
    assert.ok(html.includes('whole-ob-answer-box'), 'Must have whole-ob-answer-box for active objection responses');
    assert.ok(html.includes('renderObjectionsForStage'), 'Must have function to update objections dynamically on stage change');

    // Verify SMS constructor at the end of whole script
    assert.ok(html.includes('whole-sms-card'), 'Must have whole-sms-card at the end of whole script');
    assert.ok(html.includes('whole-sms-toggle-btn'), 'Must have toggle button to expand SMS builder downwards');
    assert.ok(html.includes('whole-sms-body'), 'Must have expandable SMS body');
    assert.ok(html.includes('w-sms-copy'), 'Must have copy button for SMS');
  });

  await t.test('17. Presentation Plan: Melentyeva / HEAD / ADMIN can manage 4-step presentation plan, cities and halls, and operators get interactive time picker on stage «Выбор времени» with auto-filled date/time variables in script lines and SMS', async () => {
    const unauthClient = createTestClient(baseUrl);

    // 1. Unauthenticated GET returns 200 (null or plan), PUT returns 401
    const unauthGet = await unauthClient.request('/api/presentation-plan');
    assert.strictEqual(unauthGet.status, 200);

    const unauthPut = await unauthClient.request('/api/presentation-plan', {
      method: 'PUT',
      body: { cities: [] }
    });
    assert.strictEqual(unauthPut.status, 401);

    // 2. Non-manager (EDITOR without addresses.manage) cannot PUT (403 forbidden)
    const editorPut = await editorClient.request('/api/presentation-plan', {
      method: 'PUT',
      body: { cities: [] }
    });
    assert.strictEqual(editorPut.status, 403);

    // 3. OWNER / Melentyeva / HEAD can PUT plan with cities, halls, days, times and per-day dayTimes
    const testPlan = {
      weekStart: '2026-11-09',
      cities: [
        {
          cityName: 'Москва',
          halls: [
            {
              hallName: 'Отель Панорама',
              days: ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'],
              times: ['10:00', '12:00', '14:00', '18:00'],
              dayTimes: {
                'Пн': ['10:00', '14:00', '18:00'],
                'Вт': ['12:00', '16:00'],
                'Ср': ['10:00', '14:00', '18:00'],
                'Чт': ['11:00', '15:00'],
                'Пт': ['10:00', '14:00'],
                'Сб': ['10:00', '13:00'],
                'Вс': ['11:00', '14:00']
              }
            },
            {
              hallName: 'ТК «Бухарест», 2 этаж',
              days: ['Пн', 'Вт', 'Ср'],
              times: ['11:00', '15:00', '19:00'],
              dayTimes: {
                'Пн': ['11:00', '15:00'],
                'Вт': ['11:00', '15:00', '19:00'],
                'Ср': ['15:00', '19:00']
              }
            }
          ]
        },
        {
          cityName: 'Воронеж',
          halls: [
            {
              hallName: 'Мартовские зайцы, 6 этаж',
              days: ['Чт', 'Пт', 'Сб', 'Вс'],
              times: ['10:00', '14:00', '18:00'],
              dayTimes: {
                'Чт': ['14:00', '18:00'],
                'Пт': ['10:00', '14:00', '18:00'],
                'Сб': ['10:00', '14:00'],
                'Вс': ['10:00', '14:00']
              }
            }
          ]
        }
      ]
    };

    const ownerPut = await ownerClient.request('/api/presentation-plan', {
      method: 'PUT',
      body: testPlan
    });
    assert.strictEqual(ownerPut.status, 200);
    const savedPlan = ownerPut.data;
    assert.strictEqual(savedPlan.weekStart, '2026-11-09');
    assert.strictEqual(savedPlan.cities.length, 2);
    assert.strictEqual(savedPlan.cities[0].halls.length, 2);
    assert.deepStrictEqual(savedPlan.cities[0].halls[0].dayTimes['Вт'], ['12:00', '16:00']);
    assert.strictEqual(savedPlan.updatedByRole, 'OWNER');

    // 4. GET returns saved plan
    const getRes = await unauthClient.request('/api/presentation-plan');
    assert.strictEqual(getRes.status, 200);
    const fetchedPlan = getRes.data;
    assert.strictEqual(fetchedPlan.weekStart, '2026-11-09');
    assert.strictEqual(fetchedPlan.cities[0].cityName, 'Москва');
    assert.deepStrictEqual(fetchedPlan.cities[0].halls[0].dayTimes['Сб'], ['10:00', '13:00']);

    // 5. Verify index.html UI elements for Presentation Plan
    const html = fs.readFileSync(path.resolve('index.html'), 'utf8');

    // Top tab & container
    assert.ok(html.includes('id="plan-tab"'), 'Must have #plan-tab in header');
    assert.ok(html.includes('id="plan-view"'), 'Must have #plan-view container');

    // Always working cities
    const alwaysCities = ['Москва', 'Санкт-Петербург', 'Ростов', 'Севастополь', 'Симферополь', 'Краснодар'];
    for (const c of alwaysCities) {
      assert.ok(html.includes(c), `Must include always working city: ${c}`);
    }

    // Stepper wizard + per-day times + built-in 2026 calendar
    assert.ok(html.includes('plan-stepper'), 'Must have stepper for wizard');
    assert.ok(html.includes('planWizardStep'), 'Must track active wizard step');
    assert.ok(html.includes('data-plan-add-hall'), 'Must allow unlimited halls with + Добавить зал');
    assert.ok(html.includes('data-plan-day-toggle'), 'Step 3 must allow day selection');
    assert.ok(html.includes('data-plan-toggle-day-time'), 'Must allow toggling time slots per day');
    assert.ok(html.includes('data-plan-add-day-time'), 'Must allow custom time slots per day');
    assert.ok(html.includes('getHallTimesForDay'), 'Must support different presentation times on different days');
    assert.ok(html.includes('BAUER_WEEK_DAYS'), 'Must support Вт, Ср, Чт, Пт, Сб, Вс, Пн cycle');
    assert.ok(html.includes('getBauerWeekDaysCalendar'), 'Must have built-in 2026 week calendar');
    assert.ok(html.includes('api_local_vault'), 'Must have local vault fallback');
    assert.ok(html.includes('pathname===\'/api/presentation-plan\''), 'Local vault must handle presentation-plan to avoid route not found');

    // Movable schedule block in Layout Editor (Макеты)
    assert.ok(html.includes("schedule:'📅 График времени'"), 'Layout editor KINDS must include schedule');
    assert.ok(html.includes('data-v4="addschedline"'), 'Layout editor must allow adding/moving schedule block');

    // Interactive time selection on stage «Выбор времени» without scroll jump
    assert.ok(html.includes('presentationScheduleMarkup'), 'Must render presentation schedule markup');
    assert.ok(html.includes('isTimeStage'), 'Must restrict default schedule table to time selection stage');
    assert.ok(html.includes('data-plan-slot-select'), 'Time buttons must have data-plan-slot-select');
    assert.ok(html.includes('refreshScheduleViewsWithoutScroll'), 'Must preserve scroll position when selecting a time slot');
    assert.ok(html.includes('savedScrolls'), 'renderCards must save and restore scroll positions of script-pane and stage-body');
    assert.ok(html.includes('fillPlanHtml'), 'Must replace {дата}, {время}, {день_недели}, {дата_время} dynamically');
    assert.ok(html.includes('mark.plan-fill'), 'Must format selected time variables with plan-fill badge');
  });
});

