/**
 * NMMS 2026-27 Mayiladuthurai District Portal - Backend
 * Deploy this as a Web App (Execute as: Me, Who has access: Anyone)
 * Bind this script to the Google Sheet that has tabs: Marks, Schools, Admin, Resources (+ EditLog)
 *
 * SECURITY MODEL
 *  - login() checks the password and returns a signed token (HMAC-SHA256). The secret lives in
 *    Script Properties as AUTH_SECRET and is created automatically on first use.
 *  - Every action except PUBLIC_ACTIONS must carry a valid, unexpired token.
 *  - A teacher token is tied to ONE school (UDISE). The server ignores any udise the browser
 *    sends, so a teacher can only read / update / delete their own school's students.
 *  - ADMIN_ACTIONS need an admin token.
 *  - Repeated wrong passwords lock that username out for 15 minutes.
 *  - To log everybody out at once (e.g. after a leak): Project Settings > Script properties >
 *    delete AUTH_SECRET. A new one is generated automatically on the next request.
 */

var TOKEN_TTL_TEACHER_MS = 24 * 60 * 60 * 1000;   // teachers sign in again after 24 hours
var TOKEN_TTL_ADMIN_MS   = 8 * 60 * 60 * 1000;    // admin after 8 hours
var MAX_LOGIN_FAILS      = 8;                     // wrong passwords allowed per username...
var LOCKOUT_SECONDS      = 15 * 60;               // ...before a 15 minute lockout
var MAX_MARK             = 200;                   // sanity limit for a single MAT or SAT value

// No token needed (aggregate numbers only, no student names / passwords)
var PUBLIC_ACTIONS = { login: true, getTestList: true, getPublicReport: true };
// Admin token needed. Everything else (getMarks, updateMark, deleteStudent, getResources) needs any valid token.
var ADMIN_ACTIONS  = { getAllSchools: true, getAnalysis: true, getTopWeak: true, addResource: true, deleteResource: true };

function doPost(e) {
  var body;
  try {
    body = JSON.parse(e.postData.contents);
  } catch (err) {
    return jsonOut({ ok: false, error: 'Bad request' });
  }
  if (!body || typeof body !== 'object') return jsonOut({ ok: false, error: 'Bad request' });
  var action = body.action;
  try {
    if (!PUBLIC_ACTIONS[action]) {
      var auth = verifyToken_(body.token);
      if (!auth) return jsonOut({ ok: false, code: 'AUTH', error: 'Session expired. Please sign in again.' });
      if (ADMIN_ACTIONS[action] && auth.role !== 'admin') {
        return jsonOut({ ok: false, code: 'FORBIDDEN', error: 'Not allowed.' });
      }
      if (auth.role === 'teacher') body.udise = auth.udise;   // a teacher can only touch their own school
      body.editor = auth.username;                             // log who really made the change
    }
    switch (action) {
      case 'login': return jsonOut(login(body.username, body.password));
      case 'getMarks': return jsonOut(getMarks(body.udise));
      case 'updateMark': return jsonOut(updateMark(body));
      case 'deleteStudent': return jsonOut(deleteStudent(body));
      case 'getAllSchools': return jsonOut(getAllSchools());
      case 'getAnalysis': return jsonOut(getAnalysis(body.test));
      case 'getResources': return jsonOut(getResources());
      case 'addResource': return jsonOut(addResource(body));
      case 'deleteResource': return jsonOut(deleteResource(body));
      case 'getTestList': return jsonOut(getTestList());
      case 'getTopWeak': return jsonOut(getTopWeak(body));
      case 'getPublicReport': return jsonOut(getPublicReport(body.test));
      default: return jsonOut({ ok: false, error: 'Unknown action' });
    }
  } catch (err) {
    return jsonOut({ ok: false, error: String(err) });
  }
}

function doGet(e) {
  return ContentService.createTextOutput('NMMS Portal API is running.');
}

function jsonOut(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function sheet(name) {
  return SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
}

function sheetToObjects(name) {
  var sh = sheet(name);
  var values = sh.getDataRange().getValues();
  var headers = values[0];
  var out = [];
  for (var i = 1; i < values.length; i++) {
    var row = values[i];
    if (row.join('') === '') continue;
    var obj = {};
    for (var j = 0; j < headers.length; j++) obj[headers[j]] = row[j];
    out.push(obj);
  }
  return out;
}

/* ---------- AUTH (tokens) ---------- */
// Optional: run once from the editor to create the signing secret and confirm auth is ready.
function setupAuth() {
  getSecret_();
  Logger.log('Auth secret is ready.');
}

function getSecret_() {
  var props = PropertiesService.getScriptProperties();
  var s = props.getProperty('AUTH_SECRET');
  if (s) return s;
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    s = props.getProperty('AUTH_SECRET');
    if (!s) {
      s = Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid();
      props.setProperty('AUTH_SECRET', s);
    }
    return s;
  } finally {
    lock.releaseLock();
  }
}

function sign_(text) {
  return Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(text, getSecret_()));
}

function makeToken_(payload, ttlMs) {
  payload.exp = Date.now() + ttlMs;
  var p = Utilities.base64EncodeWebSafe(JSON.stringify(payload));
  return p + '.' + sign_(p);
}

function safeEqual_(a, b) {
  if (a.length !== b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Returns the token payload {role, username, udise, exp, ...} or null if missing / forged / expired.
function verifyToken_(token) {
  if (!token || typeof token !== 'string') return null;
  var parts = token.split('.');
  if (parts.length !== 2) return null;
  if (!safeEqual_(sign_(parts[0]), parts[1])) return null;
  var payload;
  try {
    payload = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString());
  } catch (e) {
    return null;
  }
  if (!payload || !payload.exp || payload.exp < Date.now()) return null;
  if (payload.role !== 'admin' && payload.role !== 'teacher') return null;
  return payload;
}

/* ---------- LOGIN ---------- */
function login(username, password) {
  username = String(username || '').trim();
  password = String(password || '').trim();
  if (!username || !password) return { ok: false, error: 'Enter username and password.' };

  var cache = CacheService.getScriptCache();
  var failKey = 'fail_' + username.toLowerCase().slice(0, 60);
  var fails = Number(cache.get(failKey) || 0);
  if (fails >= MAX_LOGIN_FAILS) {
    return { ok: false, error: 'Too many wrong attempts. Please try again in 15 minutes.' };
  }

  // check Admin sheet
  var admins = sheetToObjects('Admin');
  for (var i = 0; i < admins.length; i++) {
    if (String(admins[i].Username).trim() === username && String(admins[i].Password).trim() === password) {
      cache.remove(failKey);
      var adminName = admins[i].Name || 'Admin';
      return {
        ok: true, role: 'admin', name: adminName, username: username,
        token: makeToken_({ role: 'admin', username: username, name: adminName }, TOKEN_TTL_ADMIN_MS)
      };
    }
  }
  // check Schools sheet (teacher login)
  var schools = sheetToObjects('Schools');
  for (var j = 0; j < schools.length; j++) {
    if (String(schools[j].Username).trim() === username && String(schools[j].Password).trim() === password) {
      cache.remove(failKey);
      var udise = String(schools[j].UDISE);
      return {
        ok: true, role: 'teacher', username: username,
        udise: udise,
        school: schools[j]['School Name'],
        block: schools[j].Block,
        category: schools[j].Category,
        token: makeToken_({ role: 'teacher', username: username, udise: udise }, TOKEN_TTL_TEACHER_MS)
      };
    }
  }
  cache.put(failKey, String(fails + 1), LOCKOUT_SECONDS);
  return { ok: false, error: 'Invalid username or password' };
}

/* ---------- MARKS ---------- */
function getMarks(udise) {
  udise = String(udise);
  var sh = sheet('Marks');
  var values = sh.getDataRange().getValues();
  var headers = values[0];
  var udiseCol = headers.indexOf('UDISE');
  var out = [];
  for (var i = 1; i < values.length; i++) {
    if (String(values[i][udiseCol]) === udise) {
      var obj = {};
      for (var j = 0; j < headers.length; j++) obj[headers[j]] = values[i][j];
      obj._row = i + 1; // 1-indexed sheet row (display only - updates find the row again by UDISE + Roll No + Test)
      out.push(obj);
    }
  }
  return { ok: true, rows: out };
}

// '' (or blank) = clear the mark; otherwise a number from 0 to MAX_MARK.
function parseMark_(v) {
  if (v === '' || v === null || v === undefined) return { ok: true, value: '' };
  if (typeof v === 'string' && v.trim() === '') return { ok: true, value: '' };
  var n = Number(v);
  if (!isFinite(n) || n < 0 || n > MAX_MARK) return { ok: false };
  return { ok: true, value: n };
}

function updateMark(body) {
  // body: { udise, rollNo, test, mat, sat, editor }
  var sh = sheet('Marks');
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var values = sh.getDataRange().getValues();
    var headers = values[0];
    var udiseCol = headers.indexOf('UDISE');
    var rollCol  = headers.indexOf('Roll No');
    var testCol  = headers.indexOf('Test');
    var matCol   = headers.indexOf('MAT');
    var satCol   = headers.indexOf('SAT');
    var totCol   = headers.indexOf('Total');

    var udise = String(body.udise || '').trim();
    var roll  = String(body.rollNo || '').trim();
    var test  = String(body.test || '').trim();
    if (!udise || !roll || !test) return { ok: false, error: 'Missing udise/rollNo/test' };

    var m = parseMark_(body.mat), s = parseMark_(body.sat);
    if (!m.ok || !s.ok) return { ok: false, error: 'Marks must be numbers from 0 to ' + MAX_MARK + '.' };
    var mat = m.value, sat = s.value;
    var total = (mat === '' || sat === '') ? '' : (mat + sat);

    var rowIndex = -1;
    for (var i = 1; i < values.length; i++) {
      if (String(values[i][udiseCol]).trim() === udise &&
          String(values[i][rollCol]).trim() === roll &&
          String(values[i][testCol]).trim() === test) {
        rowIndex = i + 1;
        break;
      }
    }
    if (rowIndex < 0) return { ok: false, error: 'Row not found - please refresh the page.' };

    sh.getRange(rowIndex, matCol + 1).setValue(mat);
    sh.getRange(rowIndex, satCol + 1).setValue(sat);
    sh.getRange(rowIndex, totCol + 1).setValue(total);

    logEdit({ editor: body.editor, row: rowIndex, mat: mat, sat: sat });
    return { ok: true, total: total };
  } finally {
    lock.releaseLock();
  }
}

function deleteStudent(body) {
  // body: { udise, rollNo, editor } - removes ALL test rows for that student
  var sh = sheet('Marks');
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var udise = String(body.udise || '').trim();
    var roll  = String(body.rollNo || '').trim();
    if (!udise || !roll) return { ok: false, error: 'Missing udise or rollNo' };

    var values = sh.getDataRange().getValues();
    var headers = values[0];
    var udiseCol = headers.indexOf('UDISE');
    var rollCol  = headers.indexOf('Roll No');

    var rowsToDelete = [];
    for (var i = 1; i < values.length; i++) {
      if (String(values[i][udiseCol]).trim() === udise && String(values[i][rollCol]).trim() === roll) {
        rowsToDelete.push(i + 1);
      }
    }
    if (!rowsToDelete.length) return { ok: false, error: 'Student not found (already removed?)' };

    rowsToDelete.sort(function (a, b) { return b - a; }); // bottom-to-top
    rowsToDelete.forEach(function (r) { sh.deleteRow(r); });

    var log = sheet('EditLog');
    if (log) log.appendRow([new Date(), body.editor || '', 'DELETE ' + udise + '/' + roll, '', '']);

    return { ok: true, deletedRows: rowsToDelete.length };
  } finally {
    lock.releaseLock();
  }
}

function logEdit(body) {
  var sh = sheet('EditLog');
  if (!sh) return;
  sh.appendRow([new Date(), body.editor || '', body.row, body.mat, body.sat]);
}

/* ---------- SCHOOLS (admin) ---------- */
// Never send Username / Password columns to the browser.
function getAllSchools() {
  var schools = sheetToObjects('Schools').map(function (s) {
    var out = {};
    Object.keys(s).forEach(function (k) {
      var key = String(k).toLowerCase();
      if (key === 'password' || key === 'username') return;
      out[k] = s[k];
    });
    return out;
  });
  return { ok: true, schools: schools };
}

/* ---------- RESOURCES ---------- */
function getResources() {
  return { ok: true, resources: sheetToObjects('Resources') };
}

function addResource(body) {
  var sh = sheet('Resources');
  sh.appendRow([body.category || '', body.type || '', body.title || '', body.url || '', new Date()]);
  return { ok: true };
}

function deleteResource(body) {
  var sh = sheet('Resources');
  var row = parseInt(body.row, 10);
  if (row && row > 1) sh.deleteRow(row);
  return { ok: true };
}

/* ---------- ANALYSIS (admin dashboard) ---------- */
// testFilter: omit or 'All' = combined across every test round. Or pass an exact
// Test name (e.g. 'Test1') to see just that round's completion/marks.
function getAnalysis(testFilter) {
  var marksAll = sheetToObjects('Marks');
  var allTestsSet = {};
  marksAll.forEach(function (m) { allTestsSet[m.Test] = true; });
  var testCount = Object.keys(allTestsSet).length || 1;

  var singleTest = testFilter && testFilter !== 'All';
  var marks = singleTest ? marksAll.filter(function (m) { return m.Test === testFilter; }) : marksAll;
  var maxPerStudent = singleTest ? 1 : testCount; // how many entries count as "100%" per student

  var schools = sheetToObjects('Schools');

  var byBlock = {};   // block -> {schoolsSet, studentsEntered, studentsTotal, sumTotal, countTotal}
  var bySchool = {};  // udise -> {name, block, category, entered, total, sumTotal, countTotal}

  schools.forEach(function (s) {
    var b = s.Block;
    if (!byBlock[b]) byBlock[b] = { schools: new Set(), studentsTotal: 0, studentsEntered: 0, sumTotal: 0, countTotal: 0 };
    byBlock[b].schools.add(s.UDISE);
    bySchool[s.UDISE] = {
      name: s['School Name'], block: s.Block, category: s.Category,
      studentsTotal: 0, studentsEntered: 0, sumTotal: 0, countTotal: 0
    };
  });

  var seenStudents = {}; // udise|roll -> true (count each student once for "total students")
  marks.forEach(function (m) {
    var udise = String(m.UDISE);
    var key = udise + '|' + m['Roll No'];
    var isNewStudent = !seenStudents[key];
    seenStudents[key] = true;

    var b = m.Block;
    if (!byBlock[b]) byBlock[b] = { schools: new Set(), studentsTotal: 0, studentsEntered: 0, sumTotal: 0, countTotal: 0 };
    if (!bySchool[udise]) bySchool[udise] = { name: m['School Name'], block: b, category: m.Category, studentsTotal: 0, studentsEntered: 0, sumTotal: 0, countTotal: 0 };

    if (isNewStudent) {
      byBlock[b].studentsTotal += 1;
      bySchool[udise].studentsTotal += 1;
    }

    var hasMark = m.Total !== '' && m.Total !== null && !isNaN(m.Total);
    if (hasMark) {
      byBlock[b].studentsEntered += 1;
      byBlock[b].sumTotal += Number(m.Total);
      byBlock[b].countTotal += 1;
      bySchool[udise].studentsEntered += 1;
      bySchool[udise].sumTotal += Number(m.Total);
      bySchool[udise].countTotal += 1;
    }
  });

  var blockOut = [];
  for (var b in byBlock) {
    var d = byBlock[b];
    blockOut.push({
      block: b,
      schoolCount: d.schools ? d.schools.size : 0,
      studentsTotal: d.studentsTotal,
      entriesFilled: d.studentsEntered,
      maxPerStudent: maxPerStudent,
      avgMark: d.countTotal ? Math.round((d.sumTotal / d.countTotal) * 10) / 10 : 0
    });
  }

  var schoolOut = [];
  for (var u in bySchool) {
    var d = bySchool[u];
    schoolOut.push({
      udise: u, name: d.name, block: d.block, category: d.category,
      studentsTotal: d.studentsTotal, entriesFilled: d.studentsEntered,
      maxPerStudent: maxPerStudent,
      avgMark: d.countTotal ? Math.round((d.sumTotal / d.countTotal) * 10) / 10 : 0
    });
  }

  return { ok: true, byBlock: blockOut, bySchool: schoolOut, testFilter: testFilter || 'All', testCount: testCount };
}

function getTestList() {
  var marks = sheetToObjects('Marks');
  var set = {};
  marks.forEach(function (m) { set[m.Test] = true; });
  return { ok: true, tests: Object.keys(set) };
}

/* ---------- TOP / WEAK PERFORMERS ---------- */
function getTopWeak(body) {
  var testName = body.test;
  var marks = sheetToObjects('Marks');
  var filtered = marks.filter(function (m) {
    return m.Test === testName && m.Total !== '' && m.Total !== null && !isNaN(m.Total);
  });
  filtered.sort(function (a, b) { return Number(b.Total) - Number(a.Total); });

  var top = filtered.slice(0, 10).map(function (m) {
    return { name: m['Student Name'], school: m['School Name'], block: m.Block, rollNo: m['Roll No'], total: m.Total };
  });
  var weak = filtered.slice(-10).reverse().map(function (m) {
    return { name: m['Student Name'], school: m['School Name'], block: m.Block, rollNo: m['Roll No'], total: m.Total };
  });
  return { ok: true, top: top, weak: weak, count: filtered.length };
}

/* ---------- PUBLIC READ-ONLY REPORT (no login required) ---------- */
function getPublicReport(testFilter) {
  // Same aggregate data as getAnalysis, safe to expose publicly (no student names, no passwords)
  var analysis = getAnalysis(testFilter);
  var schools = sheetToObjects('Schools');
  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    totalSchools: schools.length,
    testFilter: analysis.testFilter,
    testCount: analysis.testCount,
    byBlock: analysis.byBlock,
    bySchool: analysis.bySchool
  };
}
