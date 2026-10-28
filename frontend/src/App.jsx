import React, { useEffect, useMemo, useState } from 'react';
import { Activity, Download, FileCode, Map, Radar, Search, Terminal, Wifi } from 'lucide-react';
import { pageFromHash } from './navigation';
import { createReport } from './report';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8065';
const PAGES = [
  { id: 'escaneo', label: 'Escanear', icon: Radar },
  { id: 'resultados', label: 'Resultados', icon: Map },
  { id: 'herramientas', label: 'Herramientas', icon: Terminal },
  { id: 'inalambrico', label: 'Wi-Fi e IoT', icon: Wifi },
];

async function post(path, body) {
  const response = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok || !result.success) throw new Error(result.detail || 'La solicitud no se pudo completar.');
  return result.data;
}

function Surface({ as: Tag = 'section', variant = 'panel', className = '', children, ...props }) {
  return <Tag className={`surface surface--${variant} ${className}`} {...props}>{children}</Tag>;
}

function Empty({ icon: Icon, title, action, children }) {
  return (
    <Surface variant="empty" className="p-8 text-center">
      <Icon className="w-10 h-10 mx-auto mb-4 text-blue-300" aria-hidden="true" />
      <h2 className="text-xl font-bold text-white mb-2">{title}</h2>
      <p className="text-slate-400 mb-5">{children}</p>
      {action}
    </Surface>
  );
}

export default function NetworkScanner() {
  const [page, setPage] = useState(() => pageFromHash(window.location.hash));
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('quick');
  const [scan, setScan] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');
  const [host, setHost] = useState(null);
  const [hostLoading, setHostLoading] = useState(false);
  const [hostError, setHostError] = useState('');
  const [query, setQuery] = useState('');
  const [discovery, setDiscovery] = useState([]);
  const [discoveryDone, setDiscoveryDone] = useState(false);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [discoveryError, setDiscoveryError] = useState('');
  const [wireless, setWireless] = useState(null);
  const [wirelessLoading, setWirelessLoading] = useState(false);
  const [wirelessError, setWirelessError] = useState('');
  const [reportFormat, setReportFormat] = useState('json');
  const [report, setReport] = useState(null);

  useEffect(() => {
    const onHashChange = () => {
      setPage(pageFromHash(window.location.hash));
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  useEffect(() => () => { if (report?.url) URL.revokeObjectURL(report.url); }, [report]);

  const visibleHosts = useMemo(() => (scan?.hosts || []).filter((item) =>
    `${item.ip} ${item.hostname || ''}`.toLowerCase().includes(query.toLowerCase())
  ), [scan, query]);
  const services = useMemo(() => {
    const rows = [];
    for (const item of scan?.hosts || []) {
      for (const port of item.ports || []) {
        if (port.state === 'open') rows.push({ ip: item.ip, ...port });
      }
    }
    return rows;
  }, [scan]);

  async function runScan(event) {
    event.preventDefault();
    setScanLoading(true);
    setScanError('');
    try {
      const data = await post('/api/scan/network', { network_range: networkRange.trim(), scan_type: scanType });
      setScan(data);
      setHost(null);
      setQuery('');
      window.location.hash = '/resultados';
    } catch (error) {
      setScanError(error.message);
    } finally {
      setScanLoading(false);
    }
  }

  async function openHost(ip) {
    setHostLoading(true);
    setHostError('');
    setHost(null);
    try {
      setHost(await post('/api/scan/host', { ip }));
    } catch (error) {
      setHostError(error.message);
    } finally {
      setHostLoading(false);
    }
  }

  async function discoverHosts() {
    setDiscoveryLoading(true);
    setDiscoveryError('');
    try {
      const data = await post('/api/scan/discover', { network_range: networkRange.trim() });
      setDiscovery(data.hosts || []);
      setDiscoveryDone(true);
    } catch (error) {
      setDiscoveryError(error.message);
    } finally {
      setDiscoveryLoading(false);
    }
  }

  async function scanWireless() {
    setWirelessLoading(true);
    setWirelessError('');
    try {
      setWireless(await post('/api/scan/wireless', { network_range: networkRange.trim() }));
    } catch (error) {
      setWirelessError(error.message);
    } finally {
      setWirelessLoading(false);
    }
  }

  function generateReport() {
    if (!scan && !discoveryDone) return;
    const file = createReport(reportFormat, scan, discovery);
    const url = URL.createObjectURL(new Blob([file.body], { type: file.mime }));
    setReport({ url, filename: file.filename });
  }

  const title = PAGES.find((item) => item.id === page)?.label || 'Escanear';

  return (
    <div className="scanner-app">
      <div className="app-shell">
        <aside className="app-sidebar" aria-label="Navegación principal">
          <a className="brand-mark" href="#/escaneo" aria-label="Ir a Escanear"><Wifi size={22} /></a>
          <div className="sidebar-label">Network Scanner</div>
          <nav className="app-nav" aria-label="Páginas">
            {PAGES.map(({ id, label, icon: Icon }) => (
              <a key={id} href={`#/${id}`} aria-current={page === id ? 'page' : undefined}>
                <Icon size={18} aria-hidden="true" /><span>{label}</span>
              </a>
            ))}
          </nav>
        </aside>

        <main className="app-content" id="contenido">
          <header className="page-heading">
            <div><h1>{title}</h1></div>
            <span className="heading-status"><span /> Escáner local</span>
          </header>

          {page === 'escaneo' && (
            <Surface variant="hero" className="scan-panel">
              <div className="scan-panel-heading"><h2>Nuevo escaneo</h2><Radar size={24} aria-hidden="true" /></div>
              <form className="grid grid-cols-1 md:grid-cols-3 gap-4 scan-controls" onSubmit={runScan}>
                <div>
                  <label htmlFor="network-range" className="block mb-2">Rango de red</label>
                  <input id="network-range" className="w-full px-4 py-2 rounded-lg border" value={networkRange} onChange={(event) => setNetworkRange(event.target.value)} required spellCheck="false" />
                </div>
                <div>
                  <label htmlFor="scan-type" className="block mb-2">Tipo de escaneo</label>
                  <select id="scan-type" className="w-full px-4 py-2 rounded-lg border" value={scanType} onChange={(event) => setScanType(event.target.value)}>
                    <option value="quick">Rápido · hosts</option>
                    <option value="standard">Estándar · puertos y servicios</option>
                    <option value="deep">Profundo · sistema y scripts</option>
                  </select>
                </div>
                <button type="submit" disabled={scanLoading} className="w-full px-5 py-2 rounded-lg font-bold flex items-center justify-center gap-2">
                  <Search size={19} aria-hidden="true" />{scanLoading ? 'Escaneando…' : 'Escanear red'}
                </button>
              </form>
              {scanError && <p role="alert" className="error-message mt-5">{scanError}</p>}
              {scan && <a className="inline-block mt-5 text-blue-300 underline" href="#/resultados">Ver último resultado</a>}
            </Surface>
          )}

          {page === 'resultados' && (
            !scan ? <Empty icon={Map} title="Sin resultados" action={<a className="empty-action" href="#/escaneo">Iniciar escaneo</a>}>Ejecuta un escaneo para ver los equipos.</Empty> : (
              <div className="space-y-6">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 results-stats">
                  <Surface variant="metric" className="p-5"><p>Hosts</p><strong>{scan.total_hosts}</strong></Surface>
                  <Surface variant="metric" className="p-5"><p>Activos</p><strong>{scan.active_hosts}</strong></Surface>
                  <Surface variant="metric" className="p-5"><p>Duración</p><strong>{Number(scan.duration).toFixed(1)} s</strong></Surface>
                </div>
                <p className="text-slate-400 text-sm">Rango: <span className="font-mono text-white">{scan.network_range}</span></p>
                <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)] gap-5">
                  <Surface className="p-6">
                    <div className="panel-heading"><h2>Equipos ({visibleHosts.length})</h2><input className="search-field" aria-label="Filtrar equipos" placeholder="Buscar IP o nombre" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
                    {visibleHosts.length ? <div className="host-list">
                      {visibleHosts.map((item) => <button key={item.ip} type="button" className="host-row" onClick={() => openHost(item.ip)}>
                        <span><strong>{item.ip}</strong><small>{item.hostname || 'Sin nombre'}</small></span>
                        <span className="host-state">{item.state}</span>
                      </button>)}
                    </div> : <p className="text-slate-400">{scan.hosts.length ? 'No hay coincidencias.' : 'No se detectaron equipos.'}</p>}
                  </Surface>
                  <Surface className="p-6">
                    <h2 className="panel-title">Detalle del equipo</h2>
                    {hostLoading && <p className="text-slate-400">Consultando equipo…</p>}
                    {hostError && <p role="alert" className="error-message">{hostError}</p>}
                    {host && <div className="host-detail">
                      <strong>{host.ip}</strong>
                      {host.hostname && <p>Nombre: {host.hostname}</p>}
                      {host.mac_address && <p>MAC: {host.mac_address}</p>}
                      {host.vendor && <p>Fabricante: {host.vendor}</p>}
                      {host.os && <p>Sistema: {host.os}</p>}
                      <h3>Puertos ({host.ports?.length || 0})</h3>
                      {(host.ports || []).map((port) => <p key={`${port.protocol}-${port.number}`}>{port.number}/{port.protocol} · {port.state} · {port.service || 'Desconocido'} {port.version || ''}</p>)}
                    </div>}
                    {!host && !hostLoading && !hostError && <p className="text-slate-400">Selecciona un equipo.</p>}
                  </Surface>
                </div>
                <Surface className="p-6">
                  <h2 className="panel-title">Servicios abiertos ({services.length})</h2>
                  {services.length ? <div className="overflow-x-auto"><table className="services-table"><thead><tr><th>Equipo</th><th>Puerto</th><th>Servicio</th><th>Versión</th></tr></thead><tbody>
                    {services.map((port) => <tr key={`${port.ip}-${port.protocol}-${port.number}`}><td>{port.ip}</td><td>{port.number}/{port.protocol}</td><td>{port.service || 'Desconocido'}</td><td>{port.version || '—'}</td></tr>)}
                  </tbody></table></div> : <p className="text-slate-400">No se registraron puertos abiertos. Usa un escaneo estándar o profundo para consultar servicios.</p>}
                </Surface>
              </div>
            )
          )}

          {page === 'herramientas' && <div className="space-y-6">
            <Surface className="p-6">
              <div className="panel-heading"><h2><Activity size={22} aria-hidden="true" /> Descubrir hosts</h2><span className="font-mono text-sm text-slate-400">{networkRange}</span></div>
              <button type="button" className="action-button" onClick={discoverHosts} disabled={discoveryLoading}>{discoveryLoading ? 'Buscando…' : 'Descubrir hosts'}</button>
              {discoveryError && <p role="alert" className="error-message mt-4">{discoveryError}</p>}
              {discoveryDone && <div className="mt-5"><h3 className="mb-3">{discovery.length} equipos encontrados</h3><div className="discovery-list">{discovery.map((ip) => <span key={ip}>{ip}</span>)}</div></div>}
            </Surface>
            <Surface className="p-6">
              <div className="panel-heading"><h2><FileCode size={22} aria-hidden="true" /> Exportar reporte</h2></div>
              <div className="report-controls">
                <label htmlFor="report-format">Formato</label>
                <select id="report-format" value={reportFormat} onChange={(event) => { setReportFormat(event.target.value); setReport(null); }}>
                  <option value="json">JSON</option><option value="csv">CSV</option><option value="markdown">Markdown</option>
                </select>
                <button type="button" className="action-button" onClick={generateReport} disabled={!scan && !discoveryDone}><Download size={17} aria-hidden="true" /> Generar</button>
                {report && <a className="empty-action" href={report.url} download={report.filename}>Descargar</a>}
              </div>
              {!scan && !discoveryDone && <p className="text-slate-400 mt-4">Necesitas un escaneo o descubrimiento para generar el reporte.</p>}
            </Surface>
          </div>}

          {page === 'inalambrico' && <Surface className="p-6">
            <div className="panel-heading"><h2>Redes y dispositivos</h2><button type="button" className="action-button" onClick={scanWireless} disabled={wirelessLoading}>{wirelessLoading ? 'Escaneando…' : 'Escanear Wi-Fi e IoT'}</button></div>
            {wirelessError && <p role="alert" className="error-message">{wirelessError}</p>}
            {!wireless && !wirelessLoading && <p className="text-slate-400">Ejecuta el escaneo para ver datos de esta computadora y del rango {networkRange}.</p>}
            {wireless && <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div><h3>Redes Wi-Fi ({wireless.wireless_networks?.length || 0})</h3>
                {(wireless.wireless_networks || []).map((net, index) => <div className="data-row" key={net.bssid || index}><strong>{net.ssid || 'Red oculta'}</strong><span>{net.security || 'Seguridad desconocida'}</span><small>{net.signal == null ? 'Señal desconocida' : `Señal ${net.signal}%`}{net.channel ? ` · Canal ${net.channel}` : ''}</small></div>)}
                {!wireless.wireless_networks?.length && <p className="text-slate-400 mt-3">No se detectaron redes Wi-Fi.</p>}
              </div>
              <div><h3>Dispositivos IoT ({wireless.iot_devices?.length || 0})</h3>
                {(wireless.iot_devices || []).map((item) => <div className="data-row" key={item.ip}><strong>{item.hostname || item.ip}</strong><span>{item.vendor || 'Fabricante desconocido'}</span><small>{item.ip}{item.os ? ` · ${item.os}` : ''}</small></div>)}
                {!wireless.iot_devices?.length && <p className="text-slate-400 mt-3">No se identificaron dispositivos IoT.</p>}
              </div>
            </div>}
          </Surface>}
        </main>
      </div>
    </div>
  );
}
