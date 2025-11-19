import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Wifi, Maximize2, Minimize2, RotateCw } from 'lucide-react';

export default function D3NetworkTopology({ results }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [simulation, setSimulation] = useState(null);
  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, data: null });

  useEffect(() => {
    if (!results || !results.hosts || !svgRef.current || !containerRef.current) return;

    // Limpiar SVG anterior
    d3.select(svgRef.current).selectAll('*').remove();

    // Obtener dimensiones reales del contenedor
    const containerRect = containerRef.current.getBoundingClientRect();
    const width = containerRect.width - 32; // Restar padding
    const height = isFullscreen ? window.innerHeight - 200 : 700; // Altura fija más grande

    // Crear SVG con tamaño completo
    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', [0, 0, width, height])
      .style('background', 'rgba(15, 23, 42, 0.5)')
      .style('border-radius', '12px');

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    const g = svg.append('g');

    // Preparar datos para D3
    const router = results.hosts.find(h => h.ip.endsWith('.1')) || results.hosts[0];
    
    const nodes = results.hosts.map(host => ({
      id: host.ip,
      name: host.hostname || host.ip,
      ip: host.ip,
      state: host.state,
      ports: host.ports.length,
      vendor: host.vendor,
      os: host.os,
      isRouter: host.ip === router.ip,
      type: getDeviceType(host)
    }));

    const links = results.hosts
      .filter(h => h.ip !== router.ip)
      .map(host => ({
        source: router.ip,
        target: host.ip
      }));

    // Simulación de fuerzas con configuración más estable
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(200).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-500))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(70))
      .alphaDecay(0.02) // Desaceleración más rápida
      .velocityDecay(0.4); // Más fricción para estabilizar

    setSimulation(sim);

    // Crear enlaces
    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#475569')
      .attr('stroke-width', 3)
      .attr('stroke-dasharray', '8,4')
      .attr('opacity', 0.6);

    // Crear nodos
    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(drag(sim));

    // Círculos externos (efecto glow)
    node.append('circle')
      .attr('r', d => d.isRouter ? 50 : 40)
      .attr('fill', d => {
        if (d.isRouter) return '#1e40af';
        return d.state === 'up' ? '#059669' : '#dc2626';
      })
      .attr('opacity', 0.3)
      .attr('filter', 'blur(4px)');

    // Círculos de los nodos
    node.append('circle')
      .attr('r', d => d.isRouter ? 45 : 35)
      .attr('fill', d => {
        if (d.isRouter) return '#2563eb';
        return d.state === 'up' ? '#10b981' : '#ef4444';
      })
      .attr('stroke', d => {
        if (d.isRouter) return '#60a5fa';
        return d.state === 'up' ? '#34d399' : '#f87171';
      })
      .attr('stroke-width', 3)
      .style('cursor', 'pointer')
      .on('mouseover', function(event, d) {
        d3.select(this)
          .transition()
          .duration(200)
          .attr('r', d => d.isRouter ? 55 : 45)
          .attr('stroke-width', 5);
        
        // Mostrar tooltip React
        const rect = containerRef.current.getBoundingClientRect();
        setTooltip({
          show: true,
          x: event.clientX - rect.left,
          y: event.clientY - rect.top,
          data: d
        });
      })
      .on('mouseout', function(event, d) {
        d3.select(this)
          .transition()
          .duration(200)
          .attr('r', d => d.isRouter ? 45 : 35)
          .attr('stroke-width', 3);
        
        setTooltip({ show: false, x: 0, y: 0, data: null });
      })
      .on('mousemove', function(event) {
        const rect = containerRef.current.getBoundingClientRect();
        setTooltip(prev => ({
          ...prev,
          x: event.clientX - rect.left,
          y: event.clientY - rect.top
        }));
      });

    // Efecto de pulso para el router
    if (nodes.some(n => n.isRouter)) {
      node.filter(d => d.isRouter)
        .append('circle')
        .attr('r', 45)
        .attr('fill', 'none')
        .attr('stroke', '#60a5fa')
        .attr('stroke-width', 2)
        .attr('opacity', 0.8)
        .call(pulse);
    }

    // Iconos/Texto
    node.append('text')
      .text(d => getDeviceIcon(d.type))
      .attr('text-anchor', 'middle')
      .attr('dy', 8)
      .attr('font-size', d => d.isRouter ? '32px' : '28px')
      .style('pointer-events', 'none')
      .style('user-select', 'none');

    // Etiquetas IP
    node.append('text')
      .text(d => d.ip.split('.').slice(-2).join('.'))
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.isRouter ? 70 : 60)
      .attr('font-size', '13px')
      .attr('fill', '#cbd5e1')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .style('pointer-events', 'none');

    // Indicador de puertos abiertos
    node.filter(d => d.ports > 0)
      .append('circle')
      .attr('cx', 30)
      .attr('cy', -30)
      .attr('r', 12)
      .attr('fill', '#f59e0b')
      .attr('stroke', '#fbbf24')
      .attr('stroke-width', 2);

    node.filter(d => d.ports > 0)
      .append('text')
      .text(d => d.ports)
      .attr('x', 30)
      .attr('y', -26)
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('fill', 'white')
      .attr('font-weight', 'bold')
      .style('pointer-events', 'none');

    // Actualizar posiciones y detener después de cierto tiempo
    let tickCount = 0;
    const maxTicks = 300; // Máximo de iteraciones

    sim.on('tick', () => {
      tickCount++;
      
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node.attr('transform', d => `translate(${d.x},${d.y})`);

      // Detener la simulación después de suficientes iteraciones
      if (tickCount > maxTicks) {
        sim.stop();
      }
    });

    // Funciones auxiliares
    function drag(simulation) {
      function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.1).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
      }

      function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
      }

      function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
      }

      return d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended);
    }

    function pulse(selection) {
      selection
        .transition()
        .duration(2000)
        .attr('r', 65)
        .attr('opacity', 0)
        .on('end', function() {
          d3.select(this)
            .attr('r', 45)
            .attr('opacity', 0.8)
            .call(pulse);
        });
    }

    // Centrar la vista inicialmente
    svg.call(zoom.transform, d3.zoomIdentity);

    return () => {
      if (sim) sim.stop();
    };
  }, [results, isFullscreen]);

  const resetSimulation = () => {
    if (simulation) {
      simulation.alpha(1).restart();
      // Detener después de un tiempo
      setTimeout(() => {
        if (simulation) simulation.stop();
      }, 3000);
    }
  };

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  if (!results || !results.hosts) {
    return (
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-12 text-center border border-blue-500/20">
        <Wifi className="w-16 h-16 mx-auto mb-4 text-slate-600" />
        <p className="text-slate-400">Ejecuta un escaneo para ver la topología de red</p>
      </div>
    );
  }

  return (
    <div className={`bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20 ${
      isFullscreen ? 'fixed inset-0 z-50 m-4' : ''
    }`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Wifi className="w-7 h-7 text-blue-400" />
            Topología de Red Interactiva (D3.js)
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Arrastra los nodos • Zoom con rueda del mouse • Hover para detalles
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={resetSimulation}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-all flex items-center gap-2"
          >
            <RotateCw className="w-4 h-4" />
            Reiniciar
          </button>
          <button
            onClick={toggleFullscreen}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-all"
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Visualización D3 - Con posición relativa para el tooltip */}
      <div ref={containerRef} className="relative bg-slate-900/50 rounded-xl overflow-hidden">
        <svg ref={svgRef}></svg>
        
        {/* Tooltip con z-index alto */}
        {tooltip.show && tooltip.data && (
          <div
            className="absolute bg-slate-800 border-2 border-blue-500/50 rounded-lg p-4 shadow-2xl pointer-events-none"
            style={{
              left: `${tooltip.x + 20}px`,
              top: `${tooltip.y + 20}px`,
              zIndex: 9999,
              maxWidth: '280px',
              transform: tooltip.x > containerRef.current?.offsetWidth - 300 
                ? 'translateX(-100%) translateX(-40px)' 
                : 'none'
            }}
          >
            <div className="text-white">
              <div className="font-bold text-lg mb-3 text-blue-400 flex items-center gap-2">
                <span className="text-2xl">{getDeviceIcon(tooltip.data.type)}</span>
                {tooltip.data.name}
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">IP:</span>
                  <span className="font-mono font-semibold">{tooltip.data.ip}</span>
                </div>
                {tooltip.data.vendor && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Fabricante:</span>
                    <span className="text-white">{tooltip.data.vendor}</span>
                  </div>
                )}
                {tooltip.data.os && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Sistema:</span>
                    <span className="text-white">{tooltip.data.os}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-slate-400">Estado:</span>
                  <span className={`font-semibold ${tooltip.data.state === 'up' ? 'text-green-400' : 'text-red-400'}`}>
                    {tooltip.data.state.toUpperCase()}
                  </span>
                </div>
                {tooltip.data.ports > 0 && (
                  <div className="flex justify-between pt-2 border-t border-slate-700">
                    <span className="text-slate-400">Puertos:</span>
                    <span className="text-orange-400 font-bold">{tooltip.data.ports} abiertos</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Leyenda */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <div className="w-4 h-4 bg-blue-600 rounded-full border-2 border-blue-400"></div>
          <span>Router/Gateway</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <div className="w-4 h-4 bg-green-600 rounded-full border-2 border-green-400"></div>
          <span>Activo</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <div className="w-4 h-4 bg-red-600 rounded-full border-2 border-red-400"></div>
          <span>Inactivo</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <div className="w-4 h-4 bg-orange-500 rounded-full"></div>
          <span>Puertos abiertos</span>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <div className="w-8 h-0.5 bg-slate-600" style={{strokeDasharray: '5,5'}}></div>
          <span>Conexión</span>
        </div>
      </div>

      {/* Info de red */}
      <div className="mt-6 bg-slate-700/30 rounded-lg p-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-slate-500">Rango:</span>
            <span className="text-white ml-2 font-mono">{results.network_range}</span>
          </div>
          <div>
            <span className="text-slate-500">Topología:</span>
            <span className="text-white ml-2">Estrella</span>
          </div>
          <div>
            <span className="text-slate-500">Nodos:</span>
            <span className="text-white ml-2">{results.total_hosts}</span>
          </div>
          <div>
            <span className="text-slate-500">Activos:</span>
            <span className="text-green-400 ml-2 font-semibold">{results.active_hosts}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// Funciones auxiliares
function getDeviceType(host) {
  const hostname = (host.hostname || '').toLowerCase();
  const vendor = (host.vendor || '').toLowerCase();
  
  if (hostname.includes('router') || host.ip.endsWith('.1')) return 'router';
  if (hostname.includes('desktop') || hostname.includes('pc')) return 'desktop';
  if (hostname.includes('phone') || hostname.includes('android') || hostname.includes('iphone')) return 'phone';
  if (hostname.includes('tv')) return 'tv';
  if (hostname.includes('print')) return 'printer';
  if (hostname.includes('server')) return 'server';
  if (vendor.includes('apple')) return 'phone';
  if (vendor.includes('samsung') || vendor.includes('lg')) return 'tv';
  
  return 'device';
}

function getDeviceIcon(type) {
  const icons = {
    router: '📡',
    desktop: '🖥️',
    phone: '📱',
    tv: '📺',
    printer: '🖨️',
    server: '🖴',
    device: '💻'
  };
  return icons[type] || '💻';
}