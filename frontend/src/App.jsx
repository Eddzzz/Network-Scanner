import React, { useEffect, useMemo, useState } from 'react';
import { Wifi, Search, Activity, Server, Shield, Clock, Globe, BookOpen, FileCode, Map, BarChart3, PlayCircle, Cpu, Terminal, GitCompare, Radar, Download } from 'lucide-react';
import D3NetworkTopology from './D3NetworkTopology';

export default function NetworkScanner() {
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('quick');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);
  const [showTopology, setShowTopology] = useState(true);
  const [scanHistory, setScanHistory] = useState([]);
  const [discoverTechnique, setDiscoverTechnique] = useState('icmp');
  const [discoveredHosts, setDiscoveredHosts] = useState([]);
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState(null);
  const [reportStatus, setReportStatus] = useState(null);
  const [reportDownloadUrl, setReportDownloadUrl] = useState(null);
  const [reportFormat, setReportFormat] = useState('json');
  const [reportExtension, setReportExtension] = useState('json');
  const [wirelessScanResult, setWirelessScanResult] = useState(null);
  const [wirelessScanLoading, setWirelessScanLoading] = useState(false);
  const [wirelessScanError, setWirelessScanError] = useState(null);

  const API_URL = 'http://localhost:8000';
  const portPosterStats = useMemo(() => buildPortStats(results?.hosts || []), [results]);
  const vulnerabilityFindings = useMemo(() => buildVulnerabilityFindings(results?.hosts || []), [results]);
  const documentationInsights = useMemo(
    () => buildDocumentationInsights(results, discoveredHosts),
    [results, discoveredHosts]
  );
  const serviceMatrix = useMemo(() => buildServiceVersionMatrix(results?.hosts || []), [results]);
  const tracerouteData = useMemo(() => buildTracerouteData(results?.hosts || []), [results]);
  const wirelessInventory = useMemo(() => buildWirelessInventory(results?.hosts || []), [results]);
  const resolvedWirelessInventory = wirelessScanResult
    ? { wireless: wirelessScanResult.wireless, iot: wirelessScanResult.iot }
    : wirelessInventory;

  useEffect(() => {
    return () => {
      if (reportDownloadUrl) {
        URL.revokeObjectURL(reportDownloadUrl);
      }
    };
  }, [reportDownloadUrl]);

  const scanNetwork = async () => {
    setLoading(true);
    setError(null);
    setResults(null);
    setSelectedHost(null);

    try {
      const response = await fetch(`${API_URL}/api/scan/network`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          network_range: networkRange,
          scan_type: scanType,
        }),
      });

      const data = await response.json();

      if (data.success) {
        setResults(data.data);
        setShowTopology(true);
        const entry = {
          id: data.data.scan_id,
          range: data.data.network_range,
          scanType,
          duration: data.data.duration || 0,
          totalHosts: data.data.total_hosts || 0,
          activeHosts: data.data.active_hosts || 0,
          startedAt: data.data.scan_start,
          finishedAt: data.data.scan_end
        };
        setScanHistory((prev) => [entry, ...prev].slice(0, 6));
      } else {
        setError('Error en el escaneo');
      }
    } catch (err) {
      setError(`Error de conexión: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const scanHost = async (ip) => {
    try {
      const response = await fetch(`${API_URL}/api/scan/host`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip }),
      });

      const data = await response.json();

      if (data.success) {
        setSelectedHost(data.data);
      }
    } catch (err) {
      setError(`Error escaneando host: ${err.message}`);
    }
  };

  const discoverHosts = async () => {
    setDiscovering(true);
    setDiscoverError(null);
    try {
      const response = await fetch(`${API_URL}/api/scan/discover`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          network_range: networkRange,
          scan_type: discoverTechnique,
        }),
      });
      const data = await response.json();
      if (data.success) {
        setDiscoveredHosts(data.data.hosts || []);
      } else {
        setDiscoverError(data.detail || 'No se pudo descubrir la red');
      }
    } catch (err) {
      setDiscoverError(`Error descubriendo hosts: ${err.message}`);
    } finally {
      setDiscovering(false);
    }
  };

  const handleReportDownload = () => {
    if (reportDownloadUrl) {
      URL.revokeObjectURL(reportDownloadUrl);
      setReportDownloadUrl(null);
    }
    if (!results && !discoveredHosts.length) {
      setReportStatus('Necesitas ejecutar un escaneo o descubrimiento.');
      return;
    }
    const payload = buildReportPayload({
      networkRange,
      results,
      discoveredHosts,
      history: scanHistory,
    });

    let dataPayload = '';
    let mime = 'application/json';
    let extension = 'json';

    if (reportFormat === 'json') {
      dataPayload = JSON.stringify(payload, null, 2);
    } else if (reportFormat === 'markdown') {
      dataPayload = buildMarkdownReport(payload);
      mime = 'text/markdown';
      extension = 'md';
    } else if (reportFormat === 'csv') {
      dataPayload = buildCsvReport(payload);
      mime = 'text/csv';
      extension = 'csv';
    } else if (reportFormat === 'pdf') {
      dataPayload = buildPdfReport(payload);
      mime = 'application/pdf';
      extension = 'pdf';
    }

    const blob = new Blob([dataPayload], { type: mime });
    const url = URL.createObjectURL(blob);
    setReportDownloadUrl(url);
    setReportExtension(extension);
    setReportStatus(`Reporte ${reportFormat.toUpperCase()} generado. Descarga disponible.`);
  };

  const runWirelessScan = async () => {
    setWirelessScanLoading(true);
    setWirelessScanError(null);
    try {
      const response = await fetch(`${API_URL}/api/scan/wireless`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          network_range: networkRange,
        }),
      });
      const data = await response.json();
      if (data.success) {
        const wireless = (data.data.wireless_networks || []).map((net, idx) => ({
          id: net.bssid || `wifi-${idx}`,
          ssid: net.ssid,
          bssid: net.bssid,
          signal: net.signal,
          channel: net.channel,
          security: net.security,
        }));
        const devices = (data.data.iot_devices || []).map((device, idx) => ({
          id: device.ip || `iot-${idx}`,
          name: device.hostname || device.vendor || device.ip,
          type: device.vendor || device.os || 'IoT',
          security: device.vendor || 'Desconocido',
          ip: device.ip,
          hostname: device.hostname,
          vendor: device.vendor,
          notes: device.notes || (device.confidence ? `Confianza ${(device.confidence * 100).toFixed(0)}%` : null),
        }));
        setWirelessScanResult({
          wireless,
          iot: devices,
          scannedAt: data.data.scanned_at,
        });
      } else {
        setWirelessScanError(data.detail || 'No se pudo ejecutar el escaneo inalámbrico.');
      }
    } catch (err) {
      setWirelessScanError(`Error ejecutando escaneo inalámbrico: ${err.message}`);
    } finally {
      setWirelessScanLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-6">
      <div className="max-w-[1800px] mx-auto">
        {/* Header */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 mb-6 border border-blue-500/20">
          <div className="flex items-center gap-4">
            <div className="bg-blue-500/20 p-3 rounded-xl">
              <Wifi className="w-8 h-8 text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Network Scanner</h1>
              <p className="text-slate-400">Escaneo y mapeo de topología de red con Nmap</p>
            </div>
          </div>
        </div>

        {/* Control Panel */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 mb-6 border border-blue-500/20">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Rango de Red
              </label>
              <input
                type="text"
                value={networkRange}
                onChange={(e) => setNetworkRange(e.target.value)}
                placeholder="192.168.1.0/24"
                className="w-full px-4 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Tipo de Escaneo
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-4 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="quick">Rápido (Ping Scan)</option>
                <option value="standard">Estándar (Version + Scripts)</option>
                <option value="deep">Profundo (OS Detection)</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={scanNetwork}
                disabled={loading}
                className="w-full px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                    Escaneando...
                  </>
                ) : (
                  <>
                    <Search className="w-5 h-5" />
                    Escanear Red
                  </>
                )}
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-200">
              <strong>Error:</strong> {error}
            </div>
          )}
        </div>

        {/* Results */}
        {results && (
          <>
            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
              <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 border border-blue-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Hosts Totales</p>
                    <p className="text-3xl font-bold text-white">{results.total_hosts}</p>
                  </div>
                  <Server className="w-10 h-10 text-blue-400 opacity-50" />
                </div>
              </div>

          

              <div className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 border border-purple-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Duración</p>
                    <p className="text-3xl font-bold text-white">{results.duration.toFixed(2)}s</p>
                  </div>
                  <Clock className="w-10 h-10 text-purple-400 opacity-50" />
                </div>
              </div>

              <div className="bg-gradient-to-br from-orange-500/20 to-orange-600/20 border border-orange-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Rango</p>
                    <p className="text-xl font-bold text-white truncate">{results.network_range}</p>
                  </div>
                  <Globe className="w-10 h-10 text-orange-400 opacity-50" />
                </div>
              </div>
            </div>

            {/* Toggle para mostrar topología */}
            <div className="mb-6 flex justify-center">
              <button
                onClick={() => setShowTopology(!showTopology)}
                className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-all flex items-center gap-2"
              >
                <Wifi className="w-5 h-5" />
                {showTopology ? 'Ocultar Topología' : 'Mostrar Topología'}
              </button>
            </div>

            {/* Visualización D3.js de Topología */}
            {showTopology && (
              <div className="mb-6">
                <D3NetworkTopology results={results} />
              </div>
            )}

            {/* Grid con lista de hosts y detalles */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Hosts List */}
              <div className="lg:col-span-2 bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <Server className="w-6 h-6 text-blue-400" />
                  Hosts Detectados ({results.hosts.length})
                </h2>

                <div className="space-y-3 max-h-[600px] overflow-y-auto">
                  {results.hosts.map((host, idx) => (
                    <div
                      key={idx}
                      onClick={() => scanHost(host.ip)}
                      className="bg-slate-700/50 hover:bg-slate-700 rounded-lg p-4 cursor-pointer transition-all border border-slate-600 hover:border-blue-500"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-3">
                          <div className={`w-3 h-3 rounded-full ${host.state === 'up' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                          <div>
                            <p className="text-white font-semibold">{host.ip}</p>
                            {host.hostname && (
                              <p className="text-slate-400 text-sm">{host.hostname}</p>
                            )}
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                          host.state === 'up' 
                            ? 'bg-green-500/20 text-green-300 border border-green-500/30' 
                            : 'bg-red-500/20 text-red-300 border border-red-500/30'
                        }`}>
                          {host.state.toUpperCase()}
                        </span>
                      </div>

                      {host.vendor && (
                        <p className="text-slate-400 text-sm">
                          <span className="text-slate-500">Fabricante:</span> {host.vendor}
                        </p>
                      )}

                      {host.os && (
                        <p className="text-slate-400 text-sm">
                          <span className="text-slate-500">Sistema:</span> {host.os}
                        </p>
                      )}

                      {host.ports.length > 0 && (
                        <p className="text-blue-400 text-sm mt-2">
                          <Shield className="w-4 h-4 inline mr-1" />
                          {host.ports.length} puerto(s) abierto(s)
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Host Details */}
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <Activity className="w-6 h-6 text-blue-400" />
                  Detalles del Host
                </h2>

                {selectedHost ? (
                  <div className="space-y-4">
                    <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                      <p className="text-slate-400 text-sm">Dirección IP</p>
                      <p className="text-white font-semibold text-lg">{selectedHost.ip}</p>
                    </div>

                    {selectedHost.hostname && (
                      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <p className="text-slate-400 text-sm">Hostname</p>
                        <p className="text-white font-semibold">{selectedHost.hostname}</p>
                      </div>
                    )}

                    {selectedHost.mac_address && (
                      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <p className="text-slate-400 text-sm">MAC Address</p>
                        <p className="text-white font-mono text-sm">{selectedHost.mac_address}</p>
                      </div>
                    )}

                    {selectedHost.vendor && (
                      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <p className="text-slate-400 text-sm">Fabricante</p>
                        <p className="text-white">{selectedHost.vendor}</p>
                      </div>
                    )}

                    {selectedHost.os && (
                      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <p className="text-slate-400 text-sm">Sistema Operativo</p>
                        <p className="text-white">{selectedHost.os}</p>
                      </div>
                    )}

                    {selectedHost.ports && selectedHost.ports.length > 0 && (
                      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <p className="text-slate-400 text-sm mb-3">Puertos Abiertos</p>
                        <div className="space-y-2 max-h-[300px] overflow-y-auto">
                          {selectedHost.ports.map((port, idx) => (
                            <div key={idx} className="bg-slate-600/50 rounded p-3">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-white font-semibold">Puerto {port.number}</span>
                                <span className="text-xs px-2 py-1 bg-green-500/20 text-green-300 rounded-full">
                                  {port.state}
                                </span>
                              </div>
                              <p className="text-slate-300 text-sm">
                                {port.service} {port.version && `(${port.version})`}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-12 text-slate-400">
                    <Server className="w-16 h-16 mx-auto mb-4 opacity-30" />
                    <p>Selecciona un host de la lista para ver sus detalles</p>
                  </div>
                )}
              </div>
            </div>

            {/* Visual intelligence suite */}
            <div className="mt-10 space-y-6">
              <ScanTechniqueDiagrams activeType={scanType} />
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                <NmapOutputExamples />
                <AutoTopologyMapPreview hosts={results.hosts} networkRange={results.network_range} />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <TcpPortPosters stats={portPosterStats} />
                <ScanEfficiencyCharts history={scanHistory} />
              </div>
            </div>
          </>
        )}

        {!results && !loading && (
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-12 text-center border border-blue-500/20">
            <Wifi className="w-20 h-20 mx-auto mb-4 text-blue-400 opacity-30" />
            <h3 className="text-xl font-semibold text-white mb-2">
              Listo para escanear
            </h3>
            <p className="text-slate-400">
              Ingresa un rango de red y haz clic en "Escanear Red" para comenzar
            </p>
          </div>
        )}

        <div className="mt-12 space-y-6">
          <div className="text-center">
            <p className="text-sm uppercase tracking-[0.3em] text-blue-300">Laboratorio guiado</p>
            <h2 className="text-3xl font-bold text-white mt-2">Demostraciones de escaneo y respuesta en vivo</h2>
            <p className="text-slate-400 mt-2 max-w-4xl mx-auto">
              Practica con un escaneo simulado, contrastar tecnicas disponibles y consulta ejemplos de deteccion de
              sistema operativo y scripts NSE sin necesidad de tocar la red real.
            </p>
          </div>

          <LiveDemoScanner defaultRange={networkRange} />
          <TechniqueComparisonMatrix history={scanHistory} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <OsDetectionShowcase hosts={results?.hosts || []} />
            <NseScriptExplainer />
          </div>
        </div>

        <div className="mt-12 space-y-8">
          <HostDiscoveryPanel
            networkRange={networkRange}
            technique={discoverTechnique}
            onTechniqueChange={setDiscoverTechnique}
            onDiscover={discoverHosts}
            discovering={discovering}
            discoveredHosts={discoveredHosts}
            error={discoverError}
          />
          <PortScanPlaybook hosts={results?.hosts || []} />
          <AdvancedDetectionPanel hosts={results?.hosts || []} findings={vulnerabilityFindings} />
          <DocumentationWorkspace
            insights={documentationInsights}
            onGenerateReport={handleReportDownload}
            reportStatus={reportStatus}
            reportUrl={reportDownloadUrl}
            reportFormat={reportFormat}
            onFormatChange={setReportFormat}
            reportExtension={reportExtension}
            hasResults={Boolean(results)}
          />
        </div>

        <div className="mt-12 grid grid-cols-1 xl:grid-cols-2 gap-6">
          <ServiceVersionMatrix matrix={serviceMatrix} />
          <TracerouteTopology routes={tracerouteData} />
        </div>

        <div className="mt-8">
          <WirelessIotScanner
            inventory={resolvedWirelessInventory}
            onScan={runWirelessScan}
            scanning={wirelessScanLoading}
            error={wirelessScanError}
            lastScan={wirelessScanResult?.scannedAt}
          />
        </div>
      </div>
    </div>
  );
}

function ScanTechniqueDiagrams({ activeType }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm text-blue-300 uppercase tracking-wide">Tacticas</p>
          <h3 className="text-2xl font-bold text-white">Diagramas de tecnicas de escaneo</h3>
          <p className="text-slate-400 text-sm">Comparativa visual de los metodos disponibles</p>
        </div>
        <div className="px-4 py-2 bg-slate-700/70 rounded-full text-slate-200 text-sm font-semibold">
          Modo activo: {activeType}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
        {SCAN_TECHNIQUE_DIAGRAMS.map((diagram) => {
          const isActive = diagram.relatedTypes.includes(activeType);
          return (
            <div
              key={diagram.id}
              className={`p-4 rounded-2xl border ${
                isActive
                  ? 'border-blue-400/70 bg-blue-500/10 shadow-lg shadow-blue-900/40'
                  : 'border-slate-600/60 bg-slate-900/20'
              }`}
            >
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-white font-semibold text-lg flex items-center gap-2">
                    <BookOpen className="w-5 h-5 text-blue-300" />
                    {diagram.title}
                  </p>
                  <p className="text-slate-400 text-sm">{diagram.description}</p>
                </div>
                <span className="text-[10px] uppercase tracking-wide px-3 py-1 bg-slate-700/60 text-slate-200 rounded-full">
                  {diagram.badge}
                </span>
              </div>

              <div className="mt-4 space-y-2 font-mono text-xs text-slate-200">
                {diagram.diagram.map((line, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="text-blue-400">▶</span>
                    <span>{line}</span>
                  </div>
                ))}
              </div>

              <p className="text-xs text-slate-400 mt-4">{diagram.tip}</p>
              {isActive && (
                <div className="mt-3 text-xs text-blue-300 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>
                  Foco recomendado para el ultimo escaneo
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function NmapOutputExamples() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20">
      <div className="flex items-center gap-3">
        <FileCode className="w-8 h-8 text-amber-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Ejemplos anotados de Nmap</h3>
          <p className="text-slate-400 text-sm">Fragmentos destacados para interpretar resultados</p>
        </div>
      </div>

      <div className="mt-6 space-y-4">
        {NMAP_OUTPUT_EXAMPLES.map((example) => (
          <div
            key={example.id}
            className="bg-slate-900/40 border border-slate-700 rounded-2xl p-4 hover:border-amber-400/40 transition-all"
          >
            <div className="flex items-center justify-between text-xs text-slate-400 mb-3 flex-wrap gap-2">
              <span className="font-mono text-blue-300">{example.command}</span>
              <span className="px-3 py-1 rounded-full bg-slate-800/80 text-slate-200 uppercase tracking-wide">
                {example.focus}
              </span>
            </div>
            <pre className="bg-black/40 text-lime-300 text-xs rounded-lg p-3 overflow-x-auto shadow-inner shadow-black/40">
{example.output}
            </pre>
            <ul className="mt-3 space-y-1 text-xs text-slate-300">
              {example.annotations.map((note, idx) => (
                <li key={idx} className="flex gap-2">
                  <span className="text-amber-300 font-semibold">{note.label}:</span>
                  <span className="flex-1">{note.text}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function AutoTopologyMapPreview({ hosts = [], networkRange }) {
  const clusters = useMemo(() => buildTopologyClusters(hosts), [hosts]);
  const totalNodes = hosts.length;

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20 h-full">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-sm text-blue-300 uppercase tracking-wide">Mapas rapidos</p>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <Map className="w-6 h-6 text-blue-300" />
            Topologia autogenerada
          </h3>
          <p className="text-slate-400 text-sm">Distribucion automatica de roles detectados</p>
        </div>
        <div className="text-right">
          <p className="text-slate-400 text-xs uppercase">Rango analizado</p>
          <p className="text-white font-mono text-sm">{networkRange}</p>
          <p className="text-slate-400 text-xs">{totalNodes} nodos totales</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6">
        {clusters.map((cluster) => (
          <div
            key={cluster.id}
            className="relative border border-slate-600/70 rounded-2xl p-4 bg-slate-900/30"
          >
            <div className="flex items-center justify-between gap-2">
              <p className="text-white font-semibold">{cluster.title}</p>
              <span
                className={`text-[10px] uppercase tracking-wide px-2 py-1 rounded-full border ${
                  cluster.accent === 'blue'
                    ? 'border-blue-400 text-blue-300'
                    : cluster.accent === 'green'
                    ? 'border-green-400 text-green-300'
                    : cluster.accent === 'orange'
                    ? 'border-orange-400 text-orange-300'
                    : 'border-slate-500 text-slate-200'
                }`}
              >
                {cluster.nodes.length} nodos
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-1">{cluster.description}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {cluster.nodes.slice(0, 8).map((node) => (
                <span
                  key={`${cluster.id}-${node.ip}`}
                  className={`px-3 py-1 rounded-full text-xs font-mono border ${
                    node.state === 'up'
                      ? 'border-green-400 text-green-200'
                      : 'border-slate-500 text-slate-200'
                  }`}
                >
                  {node.ip}
                </span>
              ))}
              {cluster.nodes.length > 8 && (
                <span className="px-3 py-1 rounded-full text-xs bg-slate-700/70 text-slate-200 border border-slate-600">
                  +{cluster.nodes.length - 8} mas
                </span>
              )}
              {!cluster.nodes.length && (
                <span className="text-xs text-slate-500">Sin datos disponibles</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TcpPortPosters({ stats }) {
  const hasPorts = stats && stats.total > 0;
  const stateEntries = Object.entries(stats?.states || {}).filter(([, value]) => value > 0);

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20 h-full">
      <div className="flex items-center gap-3 flex-wrap">
        <Shield className="w-6 h-6 text-rose-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Poster de estados TCP</h3>
          <p className="text-slate-400 text-sm">
            Inventario compacto de puertos abiertos, cerrados y filtrados
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-6">
        {stateEntries.length > 0 ? (
          stateEntries.map(([state, count]) => (
            <div
              key={state}
              className="border border-slate-600/70 rounded-2xl p-4 bg-slate-900/40 flex flex-col gap-2"
            >
              <p className="text-xs uppercase tracking-wide text-slate-400">{state}</p>
              <p className="text-3xl font-bold text-white">{count}</p>
              <p className="text-slate-500 text-sm">
                {Math.round((count / stats.total) * 100 || 0)}% del total procesado
              </p>
            </div>
          ))
        ) : (
          <div className="col-span-2 text-slate-400 text-sm">
            Ejecuta un escaneo estandar o deep para obtener puertos.
          </div>
        )}
      </div>

      {hasPorts && stats.topPorts.length > 0 && (
        <div className="mt-6">
          <p className="text-slate-400 text-sm mb-3 uppercase tracking-wide">Puertos mas vistos</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {stats.topPorts.map((port) => (
              <div
                key={port.id}
                className="border border-slate-600 rounded-2xl p-4 bg-gradient-to-br from-slate-900 to-slate-800"
              >
                <p className="text-lg text-white font-semibold">
                  {port.port}/{port.protocol}
                </p>
                <p className="text-slate-400 text-sm">{port.service}</p>
                <p className="text-slate-500 text-xs mt-2">
                  Detectado en {port.count} host(s) · {port.open || 0} abiertos
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ScanEfficiencyCharts({ history }) {
  const chartData = useMemo(
    () =>
      (history || []).map((entry) => ({
        ...entry,
        duration: entry?.duration || 0,
        ratio:
          entry && entry.totalHosts
            ? Math.min(entry.activeHosts / Math.max(entry.totalHosts, 1), 1)
            : 0,
      })),
    [history]
  );

  const maxDuration = chartData.reduce((max, item) => Math.max(max, item.duration), 0) || 1;
  const polylinePoints = chartData.length
    ? chartData
        .map((entry, index) => {
          const x = (index / Math.max(chartData.length - 1, 1)) * 100;
          const y = 100 - entry.ratio * 100;
          return `${x},${y}`;
        })
        .join(' ')
    : '';

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20 h-full">
      <div className="flex items-center gap-3 flex-wrap">
        <BarChart3 className="w-6 h-6 text-emerald-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Tiempo y eficiencia de escaneo</h3>
          <p className="text-slate-400 text-sm">
            Historico reciente para ajustar estrategias de cobertura
          </p>
        </div>
      </div>

      {chartData.length ? (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
            <div>
              <p className="text-slate-400 text-sm mb-3">Duracion (s)</p>
              <div className="h-48 flex items-end gap-3">
                {chartData.map((entry, idx) => (
                  <div key={entry.id || idx} className="flex-1 flex flex-col items-center">
                    <div
                      className="w-full bg-gradient-to-t from-blue-700 to-blue-400 rounded-t-lg shadow-lg shadow-blue-900/40"
                      style={{ height: `${(entry.duration / maxDuration) * 100 || 0}%` }}
                    ></div>
                    <span className="text-xs text-slate-300 mt-2">{entry.duration.toFixed(1)}s</span>
                    <span className="text-[10px] uppercase text-slate-500">{entry.scanType}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-3">Ratio de hosts activos</p>
              <svg
                viewBox="0 0 100 100"
                className="w-full h-48 bg-slate-900/40 rounded-2xl border border-slate-700"
                preserveAspectRatio="none"
              >
                <polyline
                  fill="none"
                  stroke="#34d399"
                  strokeWidth="2"
                  points={polylinePoints}
                />
                <line x1="0" y1="50" x2="100" y2="50" stroke="#475569" strokeDasharray="4 4" />
                <line x1="0" y1="75" x2="100" y2="75" stroke="#475569" strokeDasharray="4 4" />
              </svg>
              <p className="text-xs text-slate-400 mt-2">
                Promedio actual:{' '}
                <span className="text-emerald-300 font-semibold">
                  {Math.round(
                    (chartData.reduce((sum, item) => sum + item.ratio, 0) / chartData.length) * 100
                  )}
                  %
                </span>
              </p>
            </div>
          </div>

          <div className="mt-6 space-y-2 text-xs text-slate-400">
            {chartData.map((entry, idx) => (
              <div
                key={`${entry.id || idx}-meta`}
                className="flex flex-wrap items-center justify-between border border-slate-700/70 rounded-lg px-3 py-2"
              >
                <span className="font-mono text-slate-200">{entry.range}</span>
                <span>{entry.scanType}</span>
                <span>
                  {entry.activeHosts}/{entry.totalHosts} activos
                </span>
                <span>
                  {entry.finishedAt
                    ? new Date(entry.finishedAt).toLocaleTimeString()
                    : 'sin hora'}
                </span>
              </div>
            ))}
          </div>
        </>
      ) : (
        <p className="text-slate-400 text-sm mt-6">
          Ejecuta algunos escaneos para construir un historico y comparar mejoras.
        </p>
      )}
    </div>
  );
}

function LiveDemoScanner({ defaultRange }) {
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStep, setDemoStep] = useState(0);

  useEffect(() => {
    if (!demoRunning) {
      return;
    }
    if (demoStep >= DEMO_SCAN_EVENTS.length) {
      setDemoRunning(false);
      return;
    }
    const timer = setTimeout(() => {
      setDemoStep((prev) => prev + 1);
    }, 1100);
    return () => clearTimeout(timer);
  }, [demoRunning, demoStep]);

  const startDemo = () => {
    setDemoStep(0);
    setDemoRunning(true);
  };

  const resetDemo = () => {
    setDemoRunning(false);
    setDemoStep(0);
  };

  const progress = Math.min(demoStep / DEMO_SCAN_EVENTS.length, 1);
  const decoratedEvents = DEMO_SCAN_EVENTS.map((event, idx) => {
    let status = 'pending';
    if (demoStep > idx) {
      status = 'done';
    } else if (demoStep === idx && demoRunning) {
      status = 'running';
    }
    if (!demoRunning && demoStep >= DEMO_SCAN_EVENTS.length) {
      status = 'done';
    }
    return { ...event, status };
  });

  const liveHosts = DEMO_LIVE_HOSTS.filter((host) => demoStep >= host.step);

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-emerald-400/20">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <PlayCircle className="w-6 h-6 text-emerald-300" />
            Escaneo en vivo de demostracion
          </h3>
          <p className="text-slate-400 text-sm mt-1">
            Simula una corrida completa sin tocar la red. Sigue eventos, hosts descubrimos y progreso.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={startDemo}
            disabled={demoRunning}
            className="px-4 py-2 rounded-lg text-white font-semibold bg-emerald-600 disabled:bg-slate-600 transition-all"
          >
            Iniciar demo
          </button>
          <button
            onClick={resetDemo}
            className="px-4 py-2 rounded-lg text-slate-200 border border-slate-600 hover:border-emerald-400 transition-all"
          >
            Reiniciar
          </button>
        </div>
      </div>

      <div className="mt-4">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span>Rango simulado: {defaultRange}</span>
          <span>
            {Math.min(progress * 100, 100).toFixed(0)}% completado ·{' '}
            {demoRunning ? 'Recoleccion en curso' : 'Detenido'}
          </span>
        </div>
        <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-emerald-400 to-emerald-200 transition-all duration-700"
            style={{ width: `${Math.min(progress * 100, 100)}%` }}
          ></div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mt-6">
        <div className="space-y-3">
          {decoratedEvents.map((event) => (
            <div
              key={event.id}
              className={`p-3 rounded-xl border ${
                event.status === 'running'
                  ? 'border-emerald-400 bg-emerald-500/10'
                  : event.status === 'done'
                  ? 'border-slate-600 bg-slate-800/60'
                  : 'border-slate-700 bg-slate-900/30'
              }`}
            >
              <div className="flex items-center justify-between text-sm text-white">
                <span className="font-semibold">{event.title}</span>
                <span
                  className={`text-xs uppercase tracking-wide ${
                    event.status === 'running'
                      ? 'text-emerald-300'
                      : event.status === 'done'
                      ? 'text-slate-400'
                      : 'text-slate-500'
                  }`}
                >
                  {event.status === 'running'
                    ? 'Ejecutando'
                    : event.status === 'done'
                    ? 'Listo'
                    : 'Pendiente'}
                </span>
              </div>
              <p className="text-slate-400 text-xs mt-1">{event.detail}</p>
            </div>
          ))}
        </div>

        <div className="bg-slate-900/40 border border-slate-700 rounded-2xl p-4">
          <p className="text-sm text-slate-400 mb-3 uppercase tracking-wide">Feed en tiempo real</p>
          <div className="space-y-3 max-h-[240px] overflow-y-auto pr-1">
            {liveHosts.length ? (
              liveHosts.map((host) => (
                <div key={host.ip} className="p-3 rounded-xl bg-slate-800/70 border border-slate-700">
                  <div className="flex items-center justify-between">
                    <p className="text-white font-semibold">{host.ip}</p>
                    <span className="text-xs text-emerald-300">{host.role}</span>
                  </div>
                  <p className="text-slate-400 text-xs mt-1">{host.summary}</p>
                  <div className="text-xs text-slate-500 font-mono mt-2">
                    {host.os} · {host.ports} puertos · {host.time}s
                  </div>
                </div>
              ))
            ) : (
              <p className="text-slate-500 text-sm">Inicia la demo para recibir eventos y hosts detectados.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function TechniqueComparisonMatrix({ history }) {
  const stats = useMemo(() => {
    const summary = {};
    (history || []).forEach((entry) => {
      if (!summary[entry.scanType]) {
        summary[entry.scanType] = { count: 0, duration: 0 };
      }
      summary[entry.scanType].count += 1;
      summary[entry.scanType].duration += entry.duration || 0;
    });
    return summary;
  }, [history]);

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20 overflow-x-auto">
      <div className="flex items-center gap-3 mb-4">
        <GitCompare className="w-6 h-6 text-blue-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Comparativa de tecnicas</h3>
          <p className="text-slate-400 text-sm">Evalua cobertura, ruido y tiempos de cada modalidad.</p>
        </div>
      </div>

      <table className="w-full text-left text-sm text-slate-300 min-w-[600px]">
        <thead className="text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th className="py-2 pr-3">Tecnica</th>
            <th className="py-2 pr-3">Cobertura</th>
            <th className="py-2 pr-3">Tiempo teorico</th>
            <th className="py-2 pr-3">Duracion real</th>
            <th className="py-2 pr-3">Ruido / Deteccion</th>
            <th className="py-2">Ideal para</th>
          </tr>
        </thead>
        <tbody>
          {SCAN_COMPARISON_METRICS.map((tech) => {
            const realData = stats[tech.id];
            const avgDuration =
              realData && realData.count ? (realData.duration / realData.count).toFixed(1) : null;
            return (
              <tr key={tech.id} className="border-t border-slate-700/70">
                <td className="py-3 pr-3">
                  <div className="flex items-center gap-2 text-white font-semibold">
                    <Radar className="w-4 h-4 text-blue-300" />
                    {tech.name}
                  </div>
                </td>
                <td className="py-3 pr-3 text-slate-300">{tech.coverage}</td>
                <td className="py-3 pr-3 text-slate-400">{tech.typicalTime}</td>
                <td className="py-3 pr-3">
                  {avgDuration ? (
                    <span className="text-emerald-300 font-semibold">{avgDuration}s promedio</span>
                  ) : (
                    <span className="text-slate-500 text-xs">Sin datos aun</span>
                  )}
                </td>
                <td className="py-3 pr-3 text-slate-300">{tech.noise}</td>
                <td className="py-3 text-slate-300">{tech.ideal}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function OsDetectionShowcase({ hosts = [] }) {
  const dataset = useMemo(() => {
    if (hosts.length) {
      return hosts.slice(0, 4).map((host, idx) => ({
        id: `${host.ip}-${idx}`,
        ip: host.ip,
        os: host.os || 'No identificado',
        accuracy: host.os ? 0.82 : 0.4,
        cues: host.vendor ? `Vendor detectado: ${host.vendor}` : 'Sin vendor reportado',
        signature: host.os ? 'Huella TCP/UDP coincide' : 'Informacion insuficiente',
      }));
    }
    return OS_DETECTION_SAMPLE;
  }, [hosts]);

  const avg = dataset.length
    ? dataset.reduce((sum, item) => sum + item.accuracy, 0) / dataset.length
    : 0;

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-purple-400/20 h-full">
      <div className="flex items-center gap-3">
        <Cpu className="w-6 h-6 text-purple-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Deteccion de sistemas operativos</h3>
          <p className="text-slate-400 text-sm">
            Analiza respuestas TCP/IP y huellas conocidas para perfilar hosts.
          </p>
        </div>
      </div>

      <div className="mt-4 text-xs text-slate-400">
        Confianza promedio
        <div className="h-3 bg-slate-900/50 rounded-full overflow-hidden mt-1">
          <div
            className="h-full bg-gradient-to-r from-purple-500 to-rose-400"
            style={{ width: `${Math.min(avg * 100, 100)}%` }}
          ></div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-3">
        {dataset.map((sample) => (
          <div key={sample.id} className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white font-semibold">{sample.ip}</p>
                <p className="text-slate-400 text-sm">{sample.os}</p>
              </div>
              <span className="text-xs font-semibold text-purple-300">
                {(sample.accuracy * 100).toFixed(0)}% confianza
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-3">{sample.cues}</p>
            <p className="text-slate-500 text-xs mt-1">{sample.signature}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function NseScriptExplainer() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-amber-400/30 h-full">
      <div className="flex items-center gap-3">
        <Terminal className="w-6 h-6 text-amber-300" />
        <div>
          <h3 className="text-2xl font-bold text-white">Scripts NSE con explicacion</h3>
          <p className="text-slate-400 text-sm">
            Ejecuta checks especificos y entiende el resultado antes de tocar un entorno productivo.
          </p>
        </div>
      </div>

      <div className="mt-5 space-y-4">
        {NSE_SCRIPT_EXAMPLES.map((script) => (
          <div key={script.id} className="border border-amber-400/20 rounded-2xl p-4 bg-slate-900/40">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <p className="text-white font-semibold">{script.title}</p>
              <span className="text-xs uppercase tracking-wide px-3 py-1 rounded-full bg-slate-800 text-amber-200">
                {script.category}
              </span>
            </div>
            <p className="text-slate-400 text-sm mt-2">{script.description}</p>
            <pre className="mt-3 bg-black/60 text-lime-300 text-xs rounded-lg p-3 overflow-x-auto">
{script.command}
            </pre>
            <ul className="mt-3 space-y-1 text-xs text-slate-300">
              {script.notes.map((note, idx) => (
                <li key={idx} className="flex gap-2">
                  <span className="text-amber-300 font-semibold">•</span>
                  <span>{note}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function HostDiscoveryPanel({
  networkRange,
  technique,
  onTechniqueChange,
  onDiscover,
  discovering,
  discoveredHosts,
  error,
}) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-teal-400/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-teal-200">1. Descubrimiento</p>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-teal-300" />
            Hosts activos detectados
          </h3>
          <p className="text-slate-400 text-sm">
            Selecciona la tecnica deseada y realiza un barrido de ping/arp sin afectar la red principal.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>Rango utilizado</p>
          <p className="text-white font-mono text-sm">{networkRange}</p>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-3">
        {DISCOVERY_TECHNIQUES.map((option) => {
          const isActive = option.id === technique;
          return (
            <button
              key={option.id}
              type="button"
              onClick={() => onTechniqueChange(option.id)}
              className={`p-4 rounded-2xl text-left border transition-all ${
                isActive
                  ? 'border-teal-400 bg-teal-500/10 shadow-lg shadow-teal-900/30'
                  : 'border-slate-700 bg-slate-900/20 hover:border-teal-300/40'
              }`}
            >
              <p className="text-white font-semibold">{option.title}</p>
              <p className="text-slate-400 text-sm mt-1">{option.description}</p>
              <p className="text-[11px] uppercase tracking-wide text-slate-500 mt-2">{option.coverage}</p>
            </button>
          );
        })}
      </div>

      {error && (
        <div className="mt-4 bg-red-500/20 border border-red-500/40 text-red-100 rounded-xl p-3 text-sm">
          {error}
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <button
          onClick={onDiscover}
          disabled={discovering}
          className="px-5 py-2 rounded-lg bg-teal-600 hover:bg-teal-700 text-white font-semibold disabled:bg-slate-600 transition-all"
        >
          {discovering ? 'Buscando...' : 'Descubrir hosts'}
        </button>
        <span className="text-slate-400 text-sm">
          {discoveredHosts.length} host(s) identificados con esta sesion
        </span>
      </div>

      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {discoveredHosts.length ? (
          discoveredHosts.slice(0, 12).map((host) => (
            <div key={host} className="p-3 bg-slate-900/40 border border-slate-700 rounded-xl">
              <p className="text-white font-semibold">{host}</p>
              <p className="text-slate-500 text-xs">Respuesta ICMP/ARP registrada</p>
            </div>
          ))
        ) : (
          <p className="text-slate-500 text-sm col-span-full">
            Ejecuta el descubrimiento para listar los hosts activos del segmento.
          </p>
        )}
      </div>
    </div>
  );
}

function PortScanPlaybook({ hosts = [] }) {
  const hostCount = hosts.length;
  const totalPorts = hosts.reduce((sum, host) => sum + (host.ports?.length || 0), 0);
  const serviceSet = new Set(
    hosts.flatMap((host) => (host.ports || []).map((port) => (port.service || '').toLowerCase()))
  );
  const versionHits = hosts
    .flatMap((host) => (host.ports || []).filter((port) => Boolean(port.version)))
    .length;

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-500/30">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-blue-300">2. Escaneo de puertos</p>
          <h3 className="text-2xl font-bold text-white">Playbook TCP/UDP</h3>
          <p className="text-slate-400 text-sm">
            Compara SYN, Connect y UDP para cubrir servicios, validar versiones y detectar superficies expuestas.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>Hosts con puertos: <span className="text-white font-semibold">{hostCount}</span></p>
          <p>Servicios vistos: <span className="text-white font-semibold">{serviceSet.size}</span></p>
          <p>Versiones detectadas: <span className="text-white font-semibold">{versionHits}</span></p>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        {PORT_SCAN_TECHNIQUES.map((tech) => (
          <div key={tech.id} className="border border-slate-700 rounded-2xl p-4 bg-slate-900/30 h-full flex flex-col gap-3">
            <div>
              <p className="text-white font-semibold">{tech.title}</p>
              <p className="text-slate-400 text-sm">{tech.description}</p>
            </div>
            <div className="text-xs text-slate-500 uppercase tracking-wide">{tech.coverage}</div>
            <ul className="text-sm text-slate-300 space-y-2">
              {tech.tips.map((tip, idx) => (
                <li key={idx} className="flex gap-2">
                  <span className="text-blue-300">•</span>
                  <span>{tip}</span>
                </li>
              ))}
            </ul>
            <p className="text-xs text-slate-500 mt-auto">
              Puertos procesados: <span className="text-white font-semibold">{totalPorts}</span>
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function AdvancedDetectionPanel({ hosts = [], findings }) {
  const osCount = hosts.filter((host) => Boolean(host.os)).length;
  const fingerprintCoverage = hosts.length ? Math.round((osCount / hosts.length) * 100) : 0;

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-rose-400/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-rose-300">3. Deteccion avanzada</p>
          <h3 className="text-2xl font-bold text-white">Fingerprinting, NSE y vulnerabilidades</h3>
          <p className="text-slate-400 text-sm">
            Correlaciona firmas de sistema operativo, ejecuta scripts NSE y prioriza hallazgos potenciales.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>SO identificados: <span className="text-white font-semibold">{osCount}</span></p>
          <p>Cobertura fingerprint: <span className="text-white font-semibold">{fingerprintCoverage}%</span></p>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="p-4 border border-slate-700 rounded-2xl bg-slate-900/30">
          <h4 className="text-lg text-white font-semibold mb-2">Fingerprinting de SO</h4>
          <p className="text-slate-400 text-sm mb-3">
            Analiza TTL, ventanas TCP y respuestas ICMP para construir firmas confiables.
          </p>
          <ul className="space-y-2 text-sm text-slate-300">
            <li>• Deteccion pasiva basada en huellas de Nmap</li>
            <li>• Correlacion con vendor MAC</li>
            <li>• Priorizacion por criticidad</li>
          </ul>
        </div>
        <div className="p-4 border border-slate-700 rounded-2xl bg-slate-900/30">
          <h4 className="text-lg text-white font-semibold mb-2">Scripts NSE</h4>
          <p className="text-slate-400 text-sm mb-3">Utiliza bibliotecas NSE para enumerar servicios y validar CVEs.</p>
          <ul className="space-y-2 text-sm text-slate-300">
            <li>• Ejemplos: {NSE_SCRIPT_EXAMPLES.map((s) => s.id).slice(0, 2).join(', ')}...</li>
            <li>• Configura argumentos personalizados (--script-args)</li>
            <li>• Automatiza validaciones recurrentes</li>
          </ul>
        </div>
        <div className="p-4 border border-slate-700 rounded-2xl bg-slate-900/30">
          <h4 className="text-lg text-white font-semibold mb-2">Analisis de vulnerabilidades</h4>
          {findings.length ? (
            <ul className="space-y-2 text-sm text-slate-300 max-h-48 overflow-y-auto pr-1">
              {findings.map((finding, idx) => (
                <li key={`${finding.host}-${idx}`} className="border border-rose-400/20 rounded-lg p-2">
                  <p className="text-white font-semibold">{finding.host}</p>
                  <p className="text-rose-200 text-xs">{finding.issue}</p>
                  <p className="text-slate-400 text-[11px] mt-1">{finding.recommendation}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-500 text-sm">Ejecuta un escaneo para generar hallazgos potenciales.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function DocumentationWorkspace({
  insights,
  onGenerateReport,
  reportStatus,
  reportUrl,
  reportFormat,
  onFormatChange,
  reportExtension,
  hasResults,
}) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-emerald-300/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-emerald-300">4. Documentacion</p>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileCode className="w-6 h-6 text-emerald-300" />
            Reportes y mapeo
          </h3>
          <p className="text-slate-400 text-sm">
            Aprovecha la topologia generada, redacta reportes y guarda las evidencias del escaneo.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>Topologia disponible: <span className="text-white font-semibold">{hasResults ? 'Sí' : 'No'}</span></p>
          <p>Hosts descubiertos: <span className="text-white font-semibold">{insights.discovered}</span></p>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
        {DOCUMENTATION_TASKS.map((task) => (
          <div key={task.id} className="border border-slate-700 rounded-2xl p-4 bg-slate-900/30">
            <p className="text-white font-semibold">{task.title}</p>
            <p className="text-slate-400 text-sm mt-1">{task.description}</p>
            <p className="text-xs text-slate-500 mt-2 uppercase tracking-wide">{task.output}</p>
          </div>
        ))}
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-[2fr_1fr] gap-4">
        <div className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40">
          <h4 className="text-white font-semibold mb-2">Insights resumidos</h4>
          <ul className="space-y-2 text-sm text-slate-300">
            <li>• Hosts analizados: {insights.totalHosts}</li>
            <li>• Puertos abiertos: {insights.openPorts}</li>
            <li>• Servicios clave: {insights.keyServices.join(', ') || 'Sin datos'}</li>
            <li>• Descubiertos: {insights.discovered}</li>
          </ul>
        </div>
        <div className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40 flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <span className="text-xs uppercase tracking-wide text-slate-400">Formato</span>
            <div className="flex gap-2">
              {['json', 'markdown', 'csv', 'pdf'].map((format) => (
                <button
                  key={format}
                  onClick={() => onFormatChange(format)}
                  className={`flex-1 px-3 py-1 rounded-lg text-sm ${
                    reportFormat === format
                      ? 'bg-emerald-600 text-white'
                      : 'bg-slate-700 text-slate-200 hover:bg-slate-600'
                  }`}
                  type="button"
                >
                  {format.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <button
            onClick={onGenerateReport}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg flex items-center gap-2 justify-center transition-all"
          >
            <Download className="w-4 h-4" />
            Generar {reportFormat.toUpperCase()}
          </button>
          {reportUrl && (
            <a
              href={reportUrl}
              download={`network-scan-report-${Date.now()}.${reportExtension}`}
              className="text-center text-sm text-emerald-300 underline"
            >
              Descargar reporte
            </a>
          )}
          {reportStatus && <p className="text-xs text-slate-400 text-center">{reportStatus}</p>}
        </div>
      </div>
    </div>
  );
}

function ServiceVersionMatrix({ matrix = [] }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-400/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-blue-300">Servicios</p>
          <h3 className="text-2xl font-bold text-white">Deteccion de servicios y versiones</h3>
          <p className="text-slate-400 text-sm">
            Consolida las firmas mas relevantes detectadas durante el escaneo.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>Total servicios: <span className="text-white font-semibold">{matrix.length}</span></p>
        </div>
      </div>

      {matrix.length ? (
        <div className="mt-5 overflow-x-auto">
          <table className="w-full text-sm text-slate-300 min-w-[600px]">
            <thead className="text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="py-2 text-left">Servicio</th>
                <th className="py-2 text-left">Version detectada</th>
                <th className="py-2 text-left">Hosts</th>
                <th className="py-2 text-left">Protocolo</th>
              </tr>
            </thead>
            <tbody>
              {matrix.map((item) => (
                <tr key={item.id} className="border-t border-slate-700/60">
                  <td className="py-3 text-white font-semibold">{item.service}</td>
                  <td className="py-3 text-slate-300">{item.version || 'sin version'}</td>
                  <td className="py-3 text-slate-300">{item.count}</td>
                  <td className="py-3 text-slate-400 uppercase">{item.protocol}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-slate-500 text-sm mt-4">
          Ejecuta un escaneo estandar o profundo para obtener informacion de servicios y versiones.
        </p>
      )}
    </div>
  );
}

function TracerouteTopology({ routes = [] }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-indigo-400/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-indigo-300">Topologia</p>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <Map className="w-6 h-6 text-indigo-300" />
            Traceroute y saltos analizados
          </h3>
          <p className="text-slate-400 text-sm">
            Visualiza el camino hacia hosts criticos y detecta posibles cuellos de botella.
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <p>Rutas generadas: <span className="text-white font-semibold">{routes.length}</span></p>
        </div>
      </div>

      <div className="mt-5 space-y-4 max-h-[360px] overflow-y-auto pr-1">
        {routes.length ? (
          routes.map((route) => (
            <div key={route.host} className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40">
              <div className="flex items-center justify-between">
                <p className="text-white font-semibold">{route.host}</p>
                <span className="text-xs text-slate-400">{route.hops.length} saltos</span>
              </div>
              <div className="mt-3 space-y-1">
                {route.hops.map((hop) => (
                  <div key={`${route.host}-${hop.hop}`} className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">
                      {hop.hop}. {hop.ip}
                    </span>
                    <span className="text-emerald-300">{hop.rtt} ms</span>
                  </div>
                ))}
              </div>
              <p className="text-xs text-slate-500 mt-3">{route.analysis}</p>
            </div>
          ))
        ) : (
          <p className="text-slate-500 text-sm">
            Ejecuta traceroute o usa los datos de ejemplo para planificar rutas.
          </p>
        )}
      </div>
    </div>
  );
}

function WirelessIotScanner({
  inventory = { wireless: [], iot: [] },
  onScan,
  scanning,
  error,
  lastScan,
}) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-orange-400/20">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-orange-300">Wireless/IoT</p>
          <h3 className="text-2xl font-bold text-white">Escaneo de red inalambrica e IoT</h3>
          <p className="text-slate-400 text-sm">
            Lista SSID detectados, dispositivos inteligentes y nivel de seguridad configurado.
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="text-right text-xs text-slate-400">
            <p>Redes WiFi: <span className="text-white font-semibold">{inventory.wireless.length}</span></p>
            <p>Dispositivos IoT: <span className="text-white font-semibold">{inventory.iot.length}</span></p>
            {lastScan && (
              <p className="text-[11px] text-slate-500">Último: {new Date(lastScan).toLocaleTimeString()}</p>
            )}
          </div>
          {onScan && (
            <button
              onClick={onScan}
              disabled={scanning}
              className="px-4 py-2 rounded-lg bg-orange-500 text-white text-sm hover:bg-orange-600 disabled:bg-slate-600 transition-all"
            >
              {scanning ? 'Escaneando...' : 'Escanear ahora'}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 bg-red-500/10 border border-red-500/30 text-red-100 text-sm rounded-xl p-3">
          {error}
        </div>
      )}

      <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40">
          <h4 className="text-lg text-white font-semibold mb-3">Redes inalambricas</h4>
          <div className="space-y-2">
            {inventory.wireless.length ? (
              inventory.wireless.map((net, idx) => (
                <div key={net.id || `${net.ssid}-${idx}`} className="p-3 rounded-xl bg-slate-800/80 border border-slate-700">
                  <div className="flex items-center justify-between text-sm text-white">
                    <span className="font-semibold">{net.ssid}</span>
                    <span className="text-xs text-orange-200">{net.security || 'Desconocido'}</span>
                  </div>
                  <p className="text-slate-400 text-xs mt-1">
                    {net.channel ? `Canal ${net.channel}` : 'Canal n/d'} · Intensidad{' '}
                    {net.signal !== null && net.signal !== undefined ? `${net.signal}` : 'n/d'}{' '}
                    {net.signal !== null && net.signal !== undefined ? (net.signal <= 0 ? 'dBm' : '%') : ''}
                  </p>
                  {net.bssid && <p className="text-slate-500 text-[11px] mt-1">BSSID {net.bssid}</p>}
                </div>
              ))
            ) : (
              <p className="text-slate-500 text-sm">Ejecuta el escaneo para obtener redes inalámbricas.</p>
            )}
          </div>
        </div>
        <div className="border border-slate-700 rounded-2xl p-4 bg-slate-900/40">
          <h4 className="text-lg text-white font-semibold mb-3">Inventario IoT</h4>
          <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
            {inventory.iot.length ? (
              inventory.iot.map((device, idx) => (
                <div key={device.id || `${device.ip}-${idx}`} className="p-3 rounded-xl bg-slate-800/80 border border-slate-700">
                  <div className="flex items-center justify-between text-sm text-white">
                    <span>{device.name || device.hostname || device.ip}</span>
                    <span className="text-xs text-orange-200">{device.type || 'IoT'}</span>
                  </div>
                  <p className="text-slate-400 text-xs mt-1">
                    {device.ip} · {device.security || device.vendor || 'Vendor n/d'}
                  </p>
                  {device.notes && <p className="text-slate-500 text-[11px] mt-1">{device.notes}</p>}
                </div>
              ))
            ) : (
              <p className="text-slate-500 text-sm">Sin dispositivos IoT identificados.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

const SCAN_TECHNIQUE_DIAGRAMS = [
  {
    id: 'quick',
    title: 'Ping Sweep',
    badge: 'ICMP',
    description: 'Descubre hosts activos enviando eco sin tocar puertos.',
    diagram: [
      'Scanner ── ICMP Echo ──▶ Host',
      'Host ── ICMP Echo Reply ──▶ Scanner',
      'Silencio = host potencialmente caido',
    ],
    tip: 'Ideal para reconocimiento rapido y validar el rango objetivo.',
    relatedTypes: ['quick'],
  },
  {
    id: 'standard',
    title: 'SYN + Version',
    badge: 'TCP',
    description: 'Evalua servicios enviando SYN y recopilando versiones.',
    diagram: [
      'Cliente ── SYN ──▶ Puerto',
      'Puerto ── SYN/ACK ──▶ Cliente',
      'Cliente ── RST ──▶ Puerto',
    ],
    tip: 'Brinda informacion util sin completar todo el handshake.',
    relatedTypes: ['standard'],
  },
  {
    id: 'deep',
    title: 'Deteccion Profunda',
    badge: 'OS + Scripts',
    description: 'Combina servicio, OS y NSE para perfilar hosts.',
    diagram: [
      'Escaneo TCP/UDP multi puerto',
      'Deteccion de sistema operativo',
      'Scripts NSE para seguridad',
    ],
    tip: 'Usar cuando necesitas inventario completo y evidencias.',
    relatedTypes: ['deep'],
  },
];

const NMAP_OUTPUT_EXAMPLES = [
  {
    id: 'syn',
    command: 'nmap -sS -Pn 192.168.1.0/24',
    focus: 'SYN stealth',
    output: `Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-18 21:05
Nmap scan report for 192.168.1.10
Host is up (0.0039s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.0 (protocol 2.0)
80/tcp   open  http    nginx 1.24
443/tcp  open  https   nginx 1.24 TLS 1.3
MAC Address: 00:11:22:33:44:55 (Acme Devices)`,
    annotations: [
      { label: 'Estado', text: 'STATE indica si el puerto respondio al handshake.' },
      { label: 'Version', text: 'VERSION ayuda a priorizar parches o detectar desviaciones.' },
      { label: 'Vendor', text: 'La MAC anotada facilita identificar al fabricante real.' },
    ],
  },
  {
    id: 'deep',
    command: 'nmap -A -T4 192.168.1.50',
    focus: 'Deteccion completa',
    output: `Nmap scan report for 192.168.1.50
Host is up (0.0015s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       dnsmasq 2.89
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Windows 10 Pro 19045
3389/tcp open  ms-wbt-server Terminal Services
OS details: Microsoft Windows 10 21H2
Network Distance: 1 hop`,
    annotations: [
      { label: 'Filtered', text: 'Puertos filtrados implican firewall o ACL bloqueando.' },
      { label: 'OS', text: 'Deteccion de sistema operativo confirma la huella reportada.' },
      { label: 'Servicios', text: 'Puertos RDP/SMB son buenos candidatos para hardening inmediato.' },
    ],
  },
];

const DEMO_SCAN_EVENTS = [
  {
    id: 'stage-arp',
    title: 'Descubrimiento ARP/ICMP',
    detail: 'Enviando paquetes ICMP/ARP para identificar hosts despiertos.',
  },
  {
    id: 'stage-tcp',
    title: 'Escaneo SYN selectivo',
    detail: 'Sondeando puertos de alto valor para aprender el estado inicial.',
  },
  {
    id: 'stage-os',
    title: 'Deteccion de SO',
    detail: 'Comparando huellas y tiempos de respuesta para perfilar sistemas.',
  },
  {
    id: 'stage-service',
    title: 'Enumeracion de servicios',
    detail: 'Recolectando banners y versiones para cada puerto abierto.',
  },
  {
    id: 'stage-nse',
    title: 'Scripts NSE',
    detail: 'Ejecutando scripts de seguridad sobre servicios criticos.',
  },
];

const DEMO_LIVE_HOSTS = [
  {
    ip: '192.168.1.10',
    role: 'Servidor web',
    os: 'Linux 5.x',
    ports: 3,
    time: 2.1,
    summary: 'HTTP/HTTPS responden con TLS 1.3 y nginx 1.24.',
    step: 1,
  },
  {
    ip: '192.168.1.20',
    role: 'NAS domestico',
    os: 'Synology DSM',
    ports: 4,
    time: 3.9,
    summary: 'SMB y servicios web expuestos con autenticacion basica.',
    step: 2,
  },
  {
    ip: '192.168.1.50',
    role: 'Workstation',
    os: 'Windows 11',
    ports: 2,
    time: 5.4,
    summary: 'Servicios RDP y WinRM disponibles.',
    step: 3,
  },
  {
    ip: '192.168.1.60',
    role: 'Controlador domotico',
    os: 'Embedded Linux',
    ports: 1,
    time: 6.8,
    summary: 'Puerto MQTT abierto con certificados auto firmados.',
    step: 4,
  },
];

const SCAN_COMPARISON_METRICS = [
  {
    id: 'quick',
    name: 'Quick / Ping Sweep',
    coverage: 'Hosts activos (ICMP/ARP)',
    typicalTime: '5-10s / 256 hosts',
    noise: 'Muy bajo · Dificil de detectar',
    ideal: 'Reconocimiento inicial y verificacion de alcance',
  },
  {
    id: 'standard',
    name: 'Standard / -sV -sC',
    coverage: 'Puertos TCP comunes + scripts basicos',
    typicalTime: '30-90s / 256 hosts',
    noise: 'Moderado · Actividad TCP visible',
    ideal: 'Inventarios periodicos y validacion de servicios',
  },
  {
    id: 'deep',
    name: 'Deep / -A',
    coverage: 'OS detect + NSE extendido',
    typicalTime: '2-5 min / host',
    noise: 'Alto · Recomendado en ventanas controladas',
    ideal: 'Investigaciones forenses o auditorias completas',
  },
];

const OS_DETECTION_SAMPLE = [
  {
    id: 'sample-os-1',
    ip: '192.168.1.30',
    os: 'Linux 5.4 (Ubuntu)',
    accuracy: 0.86,
    cues: 'TTL=64, ventana TCP=64240',
    signature: 'Fingerprint coincide con Ubuntu 20.04',
  },
  {
    id: 'sample-os-2',
    ip: '192.168.1.55',
    os: 'Windows 10 Pro 19045',
    accuracy: 0.9,
    cues: 'TTL=128, MSS=1460, Win=8192',
    signature: 'Patron RST + timestamp propio de Microsoft',
  },
  {
    id: 'sample-os-3',
    ip: '192.168.1.90',
    os: 'Dispositivo IoT (Linux 3.x)',
    accuracy: 0.62,
    cues: 'Puertos telnet + HTTP embebido',
    signature: 'Coincidencia parcial con fingerprint genérico',
  },
];

const NSE_SCRIPT_EXAMPLES = [
  {
    id: 'http-vuln',
    title: 'http-vuln-cve2021-41773',
    category: 'Vulnerabilidades HTTP',
    description: 'Detecta directorio traversal en Apache 2.4.49/2.4.50 y reporta rutas alcanzables.',
    command: `nmap -p80,443 --script http-vuln-cve2021-41773 <host>
# NSE output abreviado
| http-vuln-cve2021-41773:
|   VULNERABLE: Path traversal detected
|   State: VULNERABLE`,
    notes: [
      'Solo se ejecuta contra hosts con Apache vulnerable detectado por -sV.',
      'Devuelve evidencia suficiente para documentar hallazgos (ruta probada).',
    ],
  },
  {
    id: 'smb-enum',
    title: 'smb-enum-shares',
    category: 'Enumeracion SMB',
    description: 'Lista recursos compartidos y permisos de acceso anonimo en servidores Windows/Samba.',
    command: `nmap -p445 --script smb-enum-shares <host>
| smb-enum-shares:
|   ADMIN$ - Administrative share
|   PUBLIC - Read/Write`,
    notes: [
      'Permite validar configuraciones de compartidos sin autenticacion.',
      'Acompanalo con smb-os-discovery para documentar version exacta.',
    ],
  },
  {
    id: 'tls',
    title: 'ssl-enum-ciphers',
    category: 'Criptografia',
    description: 'Analiza suites TLS/SSL habilitadas y marca cifrados debiles o deprecated.',
    command: `nmap -p443 --script ssl-enum-ciphers <host>
|   TLSv1.0
|     Ciphers (weak): RC4-SHA`,
    notes: [
      'Ideal para respaldar recomendaciones de endurecimiento TLS.',
      'Agregar --script-args=ssl-enum-ciphers.mincipher=HIGH filtra suites robustas.',
    ],
  },
];

const SERVICE_MATRIX_SAMPLE = [
  { id: 'http-nginx', service: 'http', version: 'nginx 1.24', protocol: 'TCP', count: 2 },
  { id: 'ssh-openssh', service: 'ssh', version: 'OpenSSH 9.0', protocol: 'TCP', count: 1 },
  { id: 'rdp', service: 'ms-wbt-server', version: 'Windows 10 RDP', protocol: 'TCP', count: 1 },
];

const TRACEROUTE_SAMPLE = [
  {
    host: '192.168.1.10',
    hops: [
      { hop: 1, ip: '192.168.1.1', rtt: 1.2 },
      { hop: 2, ip: '187.123.45.1', rtt: 12.4 },
      { hop: 3, ip: '10.20.30.1', rtt: 22.1 },
      { hop: 4, ip: '192.168.1.10', rtt: 24.5 },
    ],
    analysis: 'Ruta corta con solo un salto WAN, ideal para monitoreo.',
  },
  {
    host: '192.168.1.50',
    hops: [
      { hop: 1, ip: '192.168.1.1', rtt: 1.1 },
      { hop: 2, ip: '172.16.0.1', rtt: 9.5 },
      { hop: 3, ip: '192.168.1.50', rtt: 12.0 },
    ],
    analysis: 'Host interno detectado tras salto intermedio, revisar ACLs.',
  },
];

const WIRELESS_SAMPLE = {
  wireless: [
    { id: 'wifi-1', ssid: 'Oficina-5G', channel: 44, signal: -48, security: 'WPA2-Enterprise' },
    { id: 'wifi-2', ssid: 'Invitados', channel: 6, signal: -60, security: 'WPA2-PSK' },
  ],
  iot: [
    { id: 'iot-1', name: 'Camara Lobby', ip: '192.168.20.15', type: 'Camara IP', security: 'Firmware 2.1' },
    { id: 'iot-2', name: 'Sensor HVAC', ip: '192.168.20.30', type: 'Sensor', security: 'TLS PSK' },
  ],
};

const DISCOVERY_TECHNIQUES = [
  {
    id: 'icmp',
    title: 'Ping Sweep (ICMP)',
    description: 'Envía paquetes ICMP echo para validar hosts activos rápidamente.',
    coverage: 'Bajo ruido · Solo ICMP',
  },
  {
    id: 'arp',
    title: 'ARP inteligente',
    description: 'Consulta la tabla ARP para descubrir dispositivos locales sin depender de ICMP.',
    coverage: 'Switching layer 2',
  },
  {
    id: 'tcp-syn',
    title: 'TCP SYN discovery',
    description: 'Envía SYN en puertos comunes para inferir la presencia del host.',
    coverage: 'Detectable · Mayor certeza',
  },
];

const PORT_SCAN_TECHNIQUES = [
  {
    id: 'syn',
    title: 'TCP SYN Stealth',
    description: 'Rapidez y bajo ruido al no completar el handshake.',
    coverage: 'Diagnostico inicial',
    tips: [
      'Identifica puertos abiertos/cerrados rápido.',
      'Se combina con -sV para banner grabbing.',
      'Ideal para grandes segmentos.',
    ],
  },
  {
    id: 'connect',
    title: 'TCP Connect (-sT)',
    description: 'Completa el handshake para servicios que requieren autenticación.',
    coverage: 'Precision maxima',
    tips: [
      'Útil cuando no se tienen privilegios raw sockets.',
      'Entrega mejores resultados para detecciones de versión.',
      'Genera registros en los servicios remotos.',
    ],
  },
  {
    id: 'udp',
    title: 'UDP Scan (-sU)',
    description: 'Evalúa servicios sin conexión como DNS, SNMP o TFTP.',
    coverage: 'Descubrimiento servicios UDP',
    tips: [
      'Combina con --top-ports 50 para reducir tiempo.',
      'Respuestas ICMP ayudan a clasificar filtrados.',
      'Recomendado junto a scripts NSE específicos.',
    ],
  },
];

const DOCUMENTATION_TASKS = [
  {
    id: 'topology',
    title: 'Mapeo de topología',
    description: 'Exporta la vista D3 o apóyate en clusters generados automáticamente.',
    output: 'Diagramas y clusters',
  },
  {
    id: 'report',
    title: 'Reportes ejecutivos',
    description: 'Resume hallazgos, tiempos de escaneo y áreas críticas.',
    output: 'JSON/Markdown',
  },
  {
    id: 'analysis',
    title: 'Análisis de resultados',
    description: 'Cruza hosts activos vs. servicios detectados para priorizar acción.',
    output: 'Insights accionables',
  },
];

const CRITICAL_SERVICES = ['http', 'https', 'ssh', 'rdp', 'smb', 'domain', 'mysql', 'mssql'];

const SAMPLE_TOPOLOGY_CLUSTERS = [
  {
    id: 'sample-gateway',
    title: 'Gateway (ejemplo)',
    accent: 'blue',
    description: '192.168.1.1 - Router simulado',
    nodes: [{ ip: '192.168.1.1', state: 'up' }],
  },
  {
    id: 'sample-active',
    title: 'Activos (ejemplo)',
    accent: 'green',
    description: 'Equipos que respondieron ICMP',
    nodes: [
      { ip: '192.168.1.20', state: 'up' },
      { ip: '192.168.1.21', state: 'up' },
      { ip: '192.168.1.60', state: 'up' },
    ],
  },
  {
    id: 'sample-silent',
    title: 'Silenciosos (ejemplo)',
    accent: 'slate',
    description: 'Hosts sin respuesta en el barrido',
    nodes: [
      { ip: '192.168.1.90', state: 'down' },
      { ip: '192.168.1.91', state: 'down' },
    ],
  },
];

const VULN_SAMPLE_FINDINGS = [
  {
    host: '192.168.1.50',
    issue: 'RDP expuesto (3389/tcp) sin restricción de origen.',
    recommendation: 'Limitar el acceso mediante VPN o listas de control.',
  },
  {
    host: '192.168.1.20',
    issue: 'SMB compartido anónimo detectado.',
    recommendation: 'Deshabilitar accesos invitados y revisar permisos.',
  },
];

const DOCUMENTATION_SAMPLE_INSIGHTS = {
  totalHosts: 4,
  openPorts: 9,
  keyServices: ['web', 'ssh', 'smb'],
  discovered: 4,
};

function buildTopologyClusters(hosts = []) {
  if (!hosts.length) {
    return SAMPLE_TOPOLOGY_CLUSTERS;
  }

  const router = hosts.find((host) => host.ip && host.ip.endsWith('.1')) || hosts[0];
  const active = hosts.filter((host) => host.state === 'up' && host.ip !== router?.ip);
  const silent = hosts.filter((host) => host.state !== 'up');
  const serviceNodes = active.filter((host) =>
    (host.ports || []).some((port) =>
      CRITICAL_SERVICES.includes((port.service || '').toLowerCase())
    )
  );

  return [
    {
      id: 'gateway',
      title: 'Nodo de borde',
      accent: 'blue',
      description: router ? `Gateway ${router.ip}` : 'No se detecto gateway',
      nodes: router ? [router] : [],
    },
    {
      id: 'active',
      title: 'Dispositivos activos',
      accent: 'green',
      description: `${active.length} host responden actualmente`,
      nodes: active,
    },
    {
      id: 'services',
      title: 'Servicios criticos',
      accent: 'orange',
      description: serviceNodes.length
        ? `${serviceNodes.length} host con servicios clave`
        : 'Sin servicios criticos detectados',
      nodes: serviceNodes.length ? serviceNodes : active.slice(0, 4),
    },
    {
      id: 'silent',
      title: 'Hosts silenciosos',
      accent: 'slate',
      description: `${silent.length} nodos no respondieron`,
      nodes: silent,
    },
  ];
}

function buildPortStats(hosts = []) {
  const stats = {
    total: 0,
    states: { open: 0, closed: 0, filtered: 0, other: 0 },
    topPorts: [],
  };
  const perPort = {};

  hosts.forEach((host) => {
    (host.ports || []).forEach((port) => {
      stats.total += 1;
      const normalizedState = (port.state || 'other').toLowerCase();
      if (stats.states[normalizedState] !== undefined) {
        stats.states[normalizedState] += 1;
      } else {
        stats.states.other += 1;
      }

      const key = `${port.number}/${(port.protocol || 'tcp').toLowerCase()}`;
      if (!perPort[key]) {
        perPort[key] = {
          id: key,
          port: port.number,
          protocol: (port.protocol || 'tcp').toLowerCase(),
          service: port.service || 'desconocido',
          count: 0,
          open: 0,
        };
      }
      perPort[key].count += 1;
      if (normalizedState === 'open') {
        perPort[key].open += 1;
      }
    });
  });

  stats.topPorts = Object.values(perPort)
    .sort((a, b) => b.count - a.count)
    .slice(0, 4);

  return stats;
}

function buildVulnerabilityFindings(hosts = []) {
  const findings = [];
  hosts.forEach((host) => {
    const openPorts = (host.ports || []).filter((port) => port.state === 'open');
    openPorts.forEach((port) => {
      if (port.number === 3389) {
        findings.push({
          host: host.ip,
          issue: 'Puerto RDP (3389) expuesto; revisar endurecimiento.',
          recommendation: 'Restringe origenes o habilita NLA/monitoreo.',
        });
      }
      if (port.number === 445) {
        findings.push({
          host: host.ip,
          issue: 'SMB disponible; verificar parches (EternalBlue).',
          recommendation: 'Aplica parches MS17-010 y deshabilita SMBv1.',
        });
      }
      if (port.service && ['http', 'https'].includes(port.service.toLowerCase()) && !port.version) {
        findings.push({
          host: host.ip,
          issue: `Servicio ${port.service.toUpperCase()} sin version identificada.`,
          recommendation: 'Ejecuta -sV/-sC o scripts http-* para ampliar contexto.',
        });
      }
    });
  });
  return findings.length ? findings : VULN_SAMPLE_FINDINGS;
}

function buildDocumentationInsights(results, discoveredHosts) {
  if (results) {
    const hosts = results.hosts || [];
    const openPorts = hosts.reduce((sum, host) => sum + (host.ports?.length || 0), 0);
    const keyServices = Array.from(
      new Set(
        hosts
          .flatMap((host) => host.ports || [])
          .map((port) => (port.service || '').toLowerCase())
          .filter(Boolean)
      )
    ).slice(0, 4);

    return {
      totalHosts: hosts.length,
      openPorts,
      keyServices,
      discovered: discoveredHosts.length || results.total_hosts || 0,
    };
  }

  if (discoveredHosts.length) {
    return {
      totalHosts: discoveredHosts.length,
      openPorts: 0,
      keyServices: [],
      discovered: discoveredHosts.length,
    };
  }

  return DOCUMENTATION_SAMPLE_INSIGHTS;
}

function buildReportPayload({ networkRange, results, discoveredHosts, history }) {
  return {
    generated_at: new Date().toISOString(),
    network_range: networkRange,
    discovery: {
      hosts: discoveredHosts,
      total: discoveredHosts.length,
    },
    scan_summary: results
      ? {
          scan_id: results.scan_id,
          total_hosts: results.total_hosts,
          active_hosts: results.active_hosts,
          duration: results.duration,
          hosts: results.hosts,
        }
      : null,
    history,
  };
}

function buildServiceVersionMatrix(hosts = []) {
  const map = {};
  hosts.forEach((host) => {
    (host.ports || []).forEach((port) => {
      if (port.state !== 'open') return;
      const key = `${(port.service || 'desconocido').toLowerCase()}-${port.version || 'none'}-${port.protocol || 'tcp'}`;
      if (!map[key]) {
        map[key] = {
          id: key,
          service: port.service || 'desconocido',
          version: port.version,
          protocol: (port.protocol || 'tcp').toUpperCase(),
          count: 0,
        };
      }
      map[key].count += 1;
    });
  });
  const matrix = Object.values(map).sort((a, b) => b.count - a.count);
  return matrix.length ? matrix : SERVICE_MATRIX_SAMPLE;
}

function buildTracerouteData(hosts = []) {
  if (!hosts.length) {
    return TRACEROUTE_SAMPLE;
  }
  return hosts.slice(0, 3).map((host, idx) => {
    const hops = [
      { hop: 1, ip: '192.168.1.1', rtt: 1.2 },
      { hop: 2, ip: '10.0.0.1', rtt: 5.4 },
      { hop: 3, ip: host.ip, rtt: 8.7 + idx },
    ];
    return {
      host: host.ip,
      hops,
      analysis: 'Ruta sintetica basada en gateway local, util para validar latencias internas.',
    };
  });
}

function buildWirelessInventory(hosts = []) {
  if (!hosts.length) {
    return WIRELESS_SAMPLE;
  }
  const iot = hosts
    .filter((host) => {
      const vendor = (host.vendor || '').toLowerCase();
      return vendor.includes('ring') || vendor.includes('philips') || vendor.includes('tuya');
    })
    .map((host, idx) => ({
      id: `${host.ip}-${idx}`,
      name: host.hostname || host.ip,
      ip: host.ip,
      type: 'IoT',
      security: host.os || 'FW propietario',
    }));
  return {
    wireless: WIRELESS_SAMPLE.wireless,
    iot: iot.length ? iot : WIRELESS_SAMPLE.iot,
  };
}

function buildMarkdownReport(payload) {
  const lines = [
    `# Network Scan Report`,
    ``,
    `- Generated: ${payload.generated_at}`,
    `- Network Range: ${payload.network_range}`,
    ``,
    `## Discovery`,
    `Hosts (${payload.discovery.total}):`,
  ];
  (payload.discovery.hosts || []).forEach((host) => lines.push(`- ${host}`));
  lines.push(``, `## Scan Summary`);
  if (payload.scan_summary) {
    lines.push(
      `- Scan ID: ${payload.scan_summary.scan_id}`,
      `- Total Hosts: ${payload.scan_summary.total_hosts}`,
      `- Active Hosts: ${payload.scan_summary.active_hosts}`,
      `- Duration: ${payload.scan_summary.duration}s`,
      ``,
      `### Hosts`
    );
    payload.scan_summary.hosts.forEach((host) => {
      lines.push(`- ${host.ip} (${host.hostname || 'sin hostname'})`);
      (host.ports || []).forEach((port) => {
        lines.push(
          `  - Port ${port.number}/${port.protocol}: ${port.service || 'svc'} ${port.version || ''} (${port.state})`
        );
      });
    });
  } else {
    lines.push('No scan data captured.');
  }
  lines.push(``, `## History`);
  (payload.history || []).forEach((entry) => {
    lines.push(
      `- ${entry.range} · ${entry.scanType} · ${entry.duration.toFixed(1)}s · ${entry.activeHosts}/${entry.totalHosts} activos`
    );
  });
  return lines.join('\n');
}

function buildCsvReport(payload) {
  const header = ['ip', 'hostname', 'port', 'protocol', 'service', 'version', 'state'];
  const rows = [header.join(',')];
  if (payload.scan_summary) {
    payload.scan_summary.hosts.forEach((host) => {
      (host.ports || []).forEach((port) => {
        rows.push(
          [
            host.ip,
            host.hostname || '',
            port.number,
            port.protocol,
            port.service || '',
            port.version || '',
            port.state,
          ].join(',')
        );
      });
    });
  }
  return rows.join('\n');
}

function buildPdfReport(payload) {
  const text = buildMarkdownReport(payload);
  const lines = text.split('\n');
  let content = 'BT /F1 10 Tf 50 780 Td ';
  lines.forEach((raw, idx) => {
    const line = escapePdfText(raw || ' ');
    if (idx === 0) {
      content += `(${line}) Tj `;
    } else {
      content += `0 -14 Td (${line}) Tj `;
    }
  });
  content += 'ET';

  let pdf = '%PDF-1.4\n';
  const offsets = [];
  const appendObject = (obj) => {
    offsets.push(pdf.length);
    pdf += `${obj}\n`;
  };

  appendObject('1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj');
  appendObject('2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj');
  appendObject(
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj'
  );
  appendObject(`4 0 obj << /Length ${content.length} >> stream\n${content}\nendstream\nendobj`);
  appendObject('5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj');

  const startXref = pdf.length;
  pdf += `xref\n0 ${offsets.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  offsets.forEach((offset) => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer << /Size ${offsets.length + 1} /Root 1 0 R >>\nstartxref\n${startXref}\n%%EOF`;

  return new TextEncoder().encode(pdf);
}

function escapePdfText(text) {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}
