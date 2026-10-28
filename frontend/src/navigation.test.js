import test from 'node:test';
import assert from 'node:assert/strict';
import { pageFromHash } from './navigation.js';

test('opens each page from its URL and falls back to scan', () => {
  assert.equal(pageFromHash('#/resultados'), 'resultados');
  assert.equal(pageFromHash('#/laboratorio'), 'escaneo');
  assert.equal(pageFromHash('#/herramientas'), 'herramientas');
  assert.equal(pageFromHash('#/inalambrico'), 'inalambrico');
  assert.equal(pageFromHash('#/desconocida'), 'escaneo');
  assert.equal(pageFromHash(''), 'escaneo');
});
