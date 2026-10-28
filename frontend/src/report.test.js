import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport } from './report.js';

const scan = { network_range: '192.168.1.0/24', hosts: [
  { ip: '192.168.1.2', hostname: 'Equipo,"uno"', state: 'up', ports: [] },
  { ip: '192.168.1.3', hostname: '', state: 'up', ports: [{ number: 80, protocol: 'tcp', state: 'open', service: 'http', version: '1.0' }] },
] };

test('CSV includes hosts without ports and escapes spreadsheet fields', () => {
  const report = createReport('csv', scan, []);
  assert.match(report.body, /192\.168\.1\.2,"Equipo,""uno"""/);
  assert.match(report.body, /192\.168\.1\.3,,up,80,tcp,open,http,1\.0/);
});

test('reports use only supplied scan and discovery data', () => {
  const report = createReport('json', null, ['192.168.1.8']);
  const data = JSON.parse(report.body);
  assert.deepEqual(data.discovery, ['192.168.1.8']);
  assert.equal(data.scan, null);
});

test('CSV exports discovery when no full scan exists', () => {
  const report = createReport('csv', null, ['192.168.1.8']);
  assert.match(report.body, /192\.168\.1\.8/);
});
