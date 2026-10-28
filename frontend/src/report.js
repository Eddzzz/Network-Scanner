const csvField = (value) => {
  let text = String(value ?? '');
  if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
};

export function createReport(format, scan, discovery) {
  const payload = { generated_at: new Date().toISOString(), scan, discovery };
  const filename = `network-scan-${payload.generated_at.slice(0, 10)}.${format === 'markdown' ? 'md' : format}`;
  if (format === 'json') return { body: JSON.stringify(payload, null, 2), mime: 'application/json', filename };
  if (format === 'markdown') {
    const lines = [
      '# Reporte de red',
      '',
      `Generado: ${payload.generated_at}`,
      `Rango: ${scan?.network_range || 'Sin escaneo de red'}`,
      '',
      `Hosts descubiertos: ${discovery.length}`,
      ...discovery.map((ip) => `- ${ip}`),
      '',
      `Hosts analizados: ${scan?.hosts?.length || 0}`,
      ...(scan?.hosts || []).flatMap((host) => [
        `- ${host.ip} ${host.hostname || ''} (${host.state})`,
        ...(host.ports || []).map((port) => `  - ${port.number}/${port.protocol}: ${port.service || 'Desconocido'} ${port.version || ''} (${port.state})`),
      ]),
    ];
    return { body: lines.join('\n'), mime: 'text/markdown', filename };
  }
  if (format === 'csv') {
    const rows = [['ip', 'hostname', 'host_state', 'port', 'protocol', 'port_state', 'service', 'version']];
    for (const host of scan?.hosts || []) {
      const ports = host.ports?.length ? host.ports : [null];
      for (const port of ports) rows.push([host.ip, host.hostname, host.state, port?.number, port?.protocol, port?.state, port?.service, port?.version]);
    }
    const scannedIps = new Set((scan?.hosts || []).map((host) => host.ip));
    for (const ip of discovery) {
      if (!scannedIps.has(ip)) rows.push([ip, '', '', '', '', '', '', '']);
    }
    return { body: rows.map((row) => row.map(csvField).join(',')).join('\r\n'), mime: 'text/csv', filename };
  }
  throw new Error('Formato de reporte no disponible');
}
