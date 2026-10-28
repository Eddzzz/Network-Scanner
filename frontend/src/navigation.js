const pages = new Set(['escaneo', 'resultados', 'herramientas', 'inalambrico']);

export function pageFromHash(hash) {
  const page = hash.replace(/^#\//, '');
  return pages.has(page) ? page : 'escaneo';
}
