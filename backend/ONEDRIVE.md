# OneDrive mediante carpeta local

El backend guarda automáticamente los reportes JSON y CSV en:

```text
C:\Users\walte\OneDrive\Nube
```

La aplicación funciona sin conexión a Internet y no utiliza Microsoft Graph, Client ID, tokens ni inicio de sesión de Microsoft. OneDrive para Windows se encarga de sincronizar esta carpeta cuando está configurado y conectado. El backend verifica la escritura local; no confirma que los archivos hayan llegado a la nube.

## Iniciar desde VS Code

Desde la raíz del proyecto:

```powershell
cd backend
.\venv\Scripts\python.exe run.py
```

Abre http://localhost:8000/docs. Para usar los endpoints de historial y OneDrive, pulsa **Authorize** e introduce el valor de `SCANNER_API_KEY` guardado en `backend/.env`.

## Configuración

La configuración de este equipo ya está preparada en `backend/.env`:

```dotenv
ONEDRIVE_LOCAL_DIR=C:/Users/walte/OneDrive/Nube
ONEDRIVE_AUTO_UPLOAD=true
SCANNER_API_KEY=tu-clave-local-ya-generada
```

Conserva la clave que ya contiene tu archivo. Reinicia el backend después de cambiar la configuración. Para otro equipo, ajusta la ruta en `.env`; si no se configura, se usa la carpeta `Nube` dentro de la ruta de OneDrive del usuario de Windows.

Cada escaneo exitoso de red, host, descubrimiento o WiFi/IoT se guarda primero en la base local `backend/data/scans.sqlite3`. Después, en segundo plano, se escriben los siguientes archivos en la carpeta configurada:

```text
scan-<history.id>.json
scan-<history.id>.csv
```

El JSON permite recuperar el registro y el CSV se puede abrir en Excel. La base SQLite permanece en el proyecto; los reportes son los archivos que se sincronizan mediante OneDrive. El frontend no necesita cambios.

## Endpoints

Estos endpoints requieren el encabezado `X-API-Key`:

| Método | Ruta | Función |
| --- | --- | --- |
| GET | `/api/history?limit=50&offset=0` | Historial local paginado y estado de guardado. |
| GET | `/api/history/{id}` | Consultar el resultado completo. |
| GET | `/api/history/{id}/export?format=json` | Descargar JSON desde la API. |
| GET | `/api/history/{id}/export?format=csv` | Descargar CSV desde la API. |
| GET | `/api/history/compare?before={id1}&after={id2}` | Comparar dispositivos y puertos por IP, con el mismo tipo de escaneo y objetivo. |
| GET | `/api/onedrive/status` | Comprobar ruta, escritura local y guardado automático. |
| POST | `/api/onedrive/scans/{id}/upload` | Guardar o volver a guardar JSON y CSV en la carpeta local. |
| GET | `/api/onedrive/files` | Listar reportes JSON presentes en la carpeta local. |
| POST | `/api/onedrive/scans/{id}/restore` | Recuperar un JSON de esa carpeta en el historial local. |

Se mantienen las rutas `/upload` y `/restore` por compatibilidad: ahora operan sobre archivos locales. `connected` en el estado indica que se puede escribir en la carpeta; `cloud_sync_verified` siempre es `false`. Por compatibilidad, el campo `sync.remote_urls` contiene ahora las rutas locales de los reportes. `synced_at` indica que ambos archivos se guardaron localmente.

Usa `history.id` devuelto por cada escaneo, el `id` del historial o el `id` de `/api/onedrive/files`. El `data.scan_id` original de un escaneo de red puede ser diferente.

## Errores y conservación de datos

- Si la carpeta está bloqueada, llena o no tiene permisos, el escaneo permanece en el historial con `sync.error`. Se puede reintentar con `/upload`.
- Se reemplaza cada reporte con una escritura temporal y un cambio de nombre, para evitar archivos parcialmente escritos. Reintentar conserva los nombres y no crea duplicados.
- Un registro solo se marca guardado cuando existen JSON y CSV completos. Si el proceso se cierra antes de terminar, los registros pendientes se pueden guardar manualmente desde la API; no hay reintentos periódicos.
- La restauración valida el formato y evita sobrescribir un registro local con el mismo ID y contenido diferente. Límite: 10 MB por reporte.
- Se ignoran archivos ajenos al patrón `scan-<UUID>.json`. No se crean enlaces públicos ni se comparten carpetas desde el backend.
- Las comparaciones usan IP como identidad; un dispositivo ausente no necesariamente está apagado. Para WiFi/IoT se comparan los dispositivos IoT, no las redes WiFi anunciadas.

## Pruebas

Desde `backend`:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

Las pruebas usan carpetas y bases temporales. Verifican guardado automático, restauración, errores de escritura, preservación de reportes existentes, exportación y comparación, sin escanear redes ni contactar con Microsoft.
