# Correos con Make (plan gratuito) desde Soporte ST

## Cómo funciona

Solo se usa el permiso de **enviar** del buzón de Soporte ST. Hay dos modos para las respuestas de los clientes. Se eligen en **Ajustes → Respuestas y revisión**.

```
ENVÍO (siempre, instantáneo)
  App ─► Firebase arma el correo completo ─(webhook + token)─► Make "Cobros ST - Envío"
      "Send a MIME message" desde Soporte ST (conexión "soporte ST"). Responder a: Soporte ST.
      Firebase guarda quién lo envió y cuándo (Dashboard → Productividad del equipo).

RESPUESTAS — Revisión manual (modo actual, plan gratuito)
  El cliente responde ─► llega a Soporte ST ─► regla de Outlook lo mueve a "gestion de cobros".
  La persona de turno lo lee y lo registra en la app: Bandeja de revisión → Respondió / Comprobante / Pago verificado.
  El escenario "Cobros ST - Respuestas" queda APAGADO.

RESPUESTAS — Automática (si suben al plan Core)
  Cada cobro lleva en copia (CC) el Mailhook de Make. Con "Responder a todos" la respuesta llega a
  "Cobros ST - Respuestas", que sube comprobantes a Google Drive y los entrega a Firebase.
  Firebase ignora los correos que vienen del propio Soporte ST.
```

**Para pasar a automático:** 1) suban a Make Core; 2) enciendan el escenario "Cobros ST - Respuestas"; 3) en Ajustes → Respuestas y revisión elijan **Automática con Make** y guarden. No hay que tocar código. Para volver a manual, hagan lo mismo al revés.

**Por qué en copia y no con una regla de reenvío:** Distelsa bloquea el reenvío automático a direcciones externas (error 550 5.7.520).

**Escenarios activos en Make** (plan gratuito: máximo 2):
- **Cobros ST - Envío** (ID 7017465): webhook `cobros-envio` → filtro *Token* → *Send a MIME/S-MIME Message* (conexión *soporte ST*).
- **Cobros ST - Respuestas** (ID 7017994, **apagado** en modo manual): Mailhook `k1l1n5lt3bv6c96dzgxlaypoqcfnys9a@hook.us2.make.com` → Router → HTTP (texto) / Iterator → filtro *Comprobante* (imagen o PDF > 15 KB) → Google Drive → HTTP.
- Los escenarios viejos ("Integration Webhooks…") quedaron **apagados**. No los borres hasta que pasen unas semanas sin problemas.

**Si Make apaga el escenario de envío con "invalid_grant":** la autorización de Microsoft venció (pasa al cambiar la contraseña de Soporte ST). Ve a *Credentials* → **soporte ST** → **Reauthorize**, entra como Soporte ST, y vuelve a encender el escenario eligiendo **Process old data**.

**Créditos (límite gratuito: 1,000 al mes):**

| Evento | Revisión manual | Automática |
|---|---|---|
| Cada cobro o respuesta de agente enviada por correo | 2 | 3 (2 + la copia que regresa a Make) |
| Cada respuesta de cliente | 0 | ~2 |
| Cada comprobante | 0 | ~3 |
| **Con ~240 cobros al mes** | **≈480 (48 %)** | **≈1,050–1,860: necesita Core** |

En el **Dashboard** (solo admin) verás el consumo estimado del mes. Se pone amarillo al 60 % y rojo al 85 %.

---|---|
| Cada cobro o respuesta de agente enviada | ~2 |
| Cada respuesta de cliente | ~2 |
| Cada comprobante | ~3 |

En el **Dashboard** (solo admin) verás el consumo estimado del mes. Se pone amarillo al 60 % y rojo al 85 %.

Alcanza para unos **130–150 cobros al mes** con su respuesta y comprobante.

---

## Paso 1 — Carpetas y regla en el Outlook de Soporte ST (5 min)

En https://outlook.office.com, con la sesión de **Soporte ST**:

1. **Carpetas:** clic derecho sobre el nombre del buzón → **Crear nueva carpeta** → `Cobros ST`. Luego clic derecho sobre `Cobros ST` → **Crear nueva subcarpeta** → `Entrada`. Repite para `Enviados`.
2. **Regla (el día del cambio):** ⚙️ → **Correo → Reglas** → edita la regla actual que manda las respuestas a Make (o crea una nueva):
   - Nombre: `Cobros ST - Entrada`
   - Condición: **El asunto incluye** → `Solicitud de pago ST-`
   - Acción 1: **Mover a** → `Cobros ST / Entrada`
   - Acción 2: **Redirigir a** → `k1l1n5lt3bv6c96dzgxlaypoqcfnys9a@hook.us2.make.com` (usa *Redirigir*, no *Reenviar*)
   - Marca **Detener el procesamiento de más reglas** → **Guardar**.

## Paso 2 — Token y carpeta de Google Drive

1. **Token secreto.** En PowerShell:
   ```powershell
   node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
   ```
   Guárdalo: es tu **MAKE_TOKEN**.
2. **Carpeta de Drive.** Usa la carpeta de comprobantes actual o crea `Cobros ST - Comprobantes` → **Compartir** → *Acceso general*: **Cualquier persona con el enlace** → **Lector**.

## Paso 3 — Escenario 1: "Cobros ST - Envío" ✅ ya creado

Webhook `cobros-envio` → filtro *Token* → **Send a MIME/S-MIME Message** (conexión *soporte ST*) con *MIME Content* = `mime`.
La URL del webhook es tu **MAKE_WEBHOOK_ENVIO** (en Make → *Webhooks* → `cobros-envio`).

## Paso 4 — Escenario 2: "Cobros ST - Respuestas" ✅ ya creado (referencia)

1. Mailhook `cobros-respuestas` ✅ ya creado.
2. **Router** con dos rutas:
   - **Ruta A (siempre): HTTP → Make a request** → `https://us-central1-gestiondecobrosst.cloudfunctions.net/recibirRespuestaCliente` · **POST** · Body type **application/x-www-form-urlencoded**:

     | Key | Value |
     |---|---|
     | token | tu MAKE_TOKEN |
     | mensaje_id | encabezado `Message-ID` del correo |
     | ticket | `subject` |
     | html | `html` (o `text`) |
     | remitente | dirección del remitente |
   - **Ruta B (si hay adjuntos):** *Iterator* sobre `attachments` → filtro (imagen > 15 KB o PDF) → **Google Drive → Upload a File** (conexión de Google actual) → **HTTP** igual que la ruta A con `mensaje_id` = Message-ID + `-adj-` + nombre del archivo, y `comprobantes` = `https://drive.google.com/file/d/` + id del archivo + `/view`.

## Paso 5 — Prueba (el día del cambio)

1. Crea un cobro con tu correo personal como cliente → **Correo**. Debe llegarte **desde Soporte ST**.
2. Responde ese correo con una foto. En Soporte ST debe caer en **Cobros ST/Entrada**, y en segundos la solicitud debe pasar a **COMPROBANTE RECIBIDO** con la foto visible en el visor.
3. Desde el visor, responde al cliente con **Enviar Correo**. Debe llegarte **en la misma conversación**.

## Si algo falla

| Síntoma | Qué revisar |
|---|---|
| La app dice "Make rechazó la llamada" | El escenario 1 está apagado, o la URL del webhook no coincide con el secreto |
| "Make se quedó sin créditos este mes" | Se agotó el plan gratuito. Se reanuda el mes siguiente, o puedes subir a Core |
| El cliente respondió y no aparece | ¿Cayó en *Cobros ST/Entrada*? ¿La regla tiene la acción *Redirigir a* con la dirección del Mailhook? Revisa el *History* del escenario 2 |
| Error 401 en el escenario 2 | El token de los módulos HTTP no coincide con MAKE_TOKEN |
| Error de conexión de Outlook en Make | Cambiaron la contraseña de Soporte ST: *Credentials* → la conexión → **Reauthorize** |
