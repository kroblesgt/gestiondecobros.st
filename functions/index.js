/**
 * Cloud Functions - Cobros ST  (versión Make, PLAN GRATUITO: 1,000 créditos/mes, 2 escenarios)
 *
 * Solo usa el permiso de ENVIAR del buzón de Soporte ST (no requiere aprobación de TI).
 *
 *   ENVÍO      enviarCorreoCobro arma el correo completo (MIME) y llama al escenario
 *              "Cobros ST - Envío" (webhook + token), que lo envía desde Soporte ST con
 *              "Send a MIME message". Las respuestas del agente llevan In-Reply-To/References
 *              del último correo del cliente: quedan en la misma conversación.
 *
 *   RESPUESTAS Dos modos, se elige en Ajustes → Respuestas y revisión (Configuracion/General.modo_respuestas):
 *              MANUAL (por defecto)  Make solo envía. Las respuestas quedan en Soporte ST y una persona
 *                                    de turno las registra en la app (Bandeja de revisión).
 *              AUTOMATICO            El Mailhook de Make va en copia (CC). Con "Responder a todos" la
 *                                    respuesta llega al escenario "Cobros ST - Respuestas", que sube
 *                                    comprobantes a Drive y la entrega en recibirRespuestaCliente.
 *                                    Gasta más créditos: necesita el plan Core de Make.
 *
 *  gestionarUsuario        (callable)   Crear / editar / eliminar / importar usuarios en Firebase Auth.
 *  enviarCorreoCobro       (callable)   Envía cobro o respuesta del agente vía Make.
 *  recibirRespuestaCliente (HTTP POST)  Make entrega aquí cada respuesta de cliente (con token).
 *  revisarSLA              (programada) Marca solicitudes sin actividad y crea UNA alerta por solicitud.
 *
 * Secretos (firebase functions:secrets:set NOMBRE):
 *  MAKE_WEBHOOK_ENVIO    URL del webhook del escenario "Cobros ST - Envío"
 *  MAKE_TOKEN            Cadena aleatoria que Make exige y envía de vuelta
 * Parámetro: SOPORTE_CORREO (por defecto soportest@distelsa.com.gt)
 */
const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { setGlobalOptions, logger } = require("firebase-functions/v2");
const { defineSecret, defineString } = require("firebase-functions/params");
const MailComposer = require("nodemailer/lib/mail-composer");
const admin = require("firebase-admin");
const { convert: htmlATexto } = require("html-to-text");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();
const { FieldValue } = admin.firestore;

setGlobalOptions({ region: "us-central1", maxInstances: 10 });

const MAKE_WEBHOOK_ENVIO = defineSecret("MAKE_WEBHOOK_ENVIO");
const SOPORTE_CORREO = defineString("SOPORTE_CORREO", { default: "soportest@distelsa.com.gt", description: "Buzón desde el que se envían los cobros" });
// Dirección del Mailhook de Make ("Cobros ST - Respuestas"). Va en copia (CC) del correo de cobro:
// con "Responder a todos" la respuesta llega a Make sin reenvío (Distelsa bloquea el reenvío
// externo) y también queda en el buzón de Soporte ST, en la misma conversación.
const MAKE_MAILHOOK = defineString("MAKE_MAILHOOK", { default: "k1l1n5lt3bv6c96dzgxlaypoqcfnys9a@hook.us2.make.com", description: "Mailhook de Make que recibe las respuestas de los clientes" });
const MAKE_TOKEN = defineSecret("MAKE_TOKEN");


// Debe coincidir con DOMINIO_LOGIN en public/index.html y en scripts/migrar-usuarios.js
const DOMINIO_LOGIN = "cobros-st.local";
const ROLES_ADMIN = ["ADMIN", "ADMINISTRADOR"];
const ESTATUS_BASE_MOTOR = {
  "ENVIADO": "ESPERA", "RECIBIDO": "ESPERA", "ERROR EN ENVÍO": "ERROR", "COMPROBANTE RECIBIDO": "ESPERA",
  "COMPLETADO": "EXITO", "PAUSADO": "INACTIVO", "ANULADO": "INACTIVO",
};
const CUENTA_DEFECTO = { banco: "Banco Industrial", tipo: "Monetaria", numero: "099-000577-9", titular: "DISTELSA SERVICIO TECNICO" };
const MSG_VACIOS = ["Sin mensaje reciente", "[Respuesta vacía o sin texto detectado]", "[Texto vacío]"];

// ------------------------------------------------------------------ utilidades
const esc = (v) => String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const escBr = (v) => esc(v).replace(/\r?\n/g, "<br>");
const safeUrl = (u) => { const s = String(u || "").trim(); return /^https?:\/\//i.test(s) ? s : ""; };
const esAdminRol = (rol) => ROLES_ADMIN.includes(String(rol || "").toUpperCase());
const toDate = (v) => { if (!v) return null; if (typeof v.toDate === "function") return v.toDate(); const d = new Date(v); return isNaN(d) ? null : d; };
const ID_VALIDO = /^[A-Za-z0-9._-]{2,64}$/;

function motorDe(estatus, catalogos) {
  const cat = catalogos?.estatus_categorias?.[estatus];
  const comp = catalogos?.categorias_comportamiento || {};
  if (cat && comp[cat]) return comp[cat];
  if (ESTATUS_BASE_MOTOR[estatus]) return ESTATUS_BASE_MOTOR[estatus];
  return comp["General"] || "ESPERA";
}

function requireAuth(request) {
  if (!request.auth || !request.auth.token || !request.auth.token.rol) {
    throw new HttpsError("unauthenticated", "Debes iniciar sesión.");
  }
  return request.auth.token;
}

async function tieneModulo(rol, modulo) {
  if (esAdminRol(rol)) return true;
  const snap = await db.doc(`Roles/${rol}`).get();
  const permisos = snap.exists ? String(snap.data().permisos || "") : "";
  return permisos === "ALL" || permisos.split(",").includes(modulo);
}

function passwordTemporal() {
  // 12 caracteres sin ambigüedades (sin 0/O, 1/l/I)
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(12);
  return Array.from(bytes, (b) => abc[b % abc.length]).join("");
}


// ================================================================== USUARIOS
async function guardarUsuario(datos, llamanteEsAdmin, { soloSiNuevoPassword = false } = {}) {
  const id = String(datos.id || "").trim();
  const nombre = String(datos.nombre || "").trim();
  const rol = String(datos.rol || "").trim().toUpperCase();
  const campanas = Array.isArray(datos.campanas) ? datos.campanas.map((c) => String(c).trim()).filter(Boolean).slice(0, 30) : [];

  if (!ID_VALIDO.test(id)) throw new HttpsError("invalid-argument", `ID inválido "${id}". Usa 2-64 letras, números, punto, guion o guion bajo.`);
  if (!nombre) throw new HttpsError("invalid-argument", "El nombre es obligatorio.");
  if (!rol) throw new HttpsError("invalid-argument", "El rol es obligatorio.");
  if (esAdminRol(rol) && !llamanteEsAdmin) throw new HttpsError("permission-denied", "Solo un administrador puede asignar el rol de administrador.");
  if (!esAdminRol(rol)) {
    const rolSnap = await db.doc(`Roles/${rol}`).get();
    if (!rolSnap.exists) throw new HttpsError("invalid-argument", `El rol "${rol}" no existe.`);
  }

  // Correo real opcional: con él la persona entra y puede recuperar su contraseña. Sin él, se usa el ID.
  const correo = String(datos.correo || "").trim().toLowerCase();
  if (correo && !/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(correo)) throw new HttpsError("invalid-argument", "El correo no es válido.");
  const email = correo || `${id.toLowerCase()}@${DOMINIO_LOGIN}`;
  let existente = null;
  try { existente = await admin.auth().getUser(id); } catch (e) { if (e.code !== "auth/user-not-found") throw e; }

  if (existente && esAdminRol(existente.customClaims?.rol) && !llamanteEsAdmin) {
    throw new HttpsError("permission-denied", "No puedes modificar a un administrador.");
  }

  let passwordGenerada = null;
  let password = datos.password ? String(datos.password) : null;
  if (password && password.length < 6) throw new HttpsError("invalid-argument", "La contraseña debe tener al menos 6 caracteres.");

  if (existente && datos.nuevo === true) {
    throw new HttpsError("already-exists", `El usuario "${id}" ya existe. Edítalo desde la tabla.`);
  }
  if (existente) {
    const cambios = { displayName: nombre, email };
    if (password && !soloSiNuevoPassword) cambios.password = password;
    // La importación no trae correo: no se toca el que ya tenga.
    if (soloSiNuevoPassword && !correo) delete cambios.email;
    try { await admin.auth().updateUser(id, cambios); }
    catch (e) { if (e.code === "auth/email-already-exists") throw new HttpsError("already-exists", `El correo ${email} ya lo usa otro usuario.`); throw e; }
  } else {
    if (!password && datos.nuevo === false) {
      throw new HttpsError("failed-precondition", "Este usuario todavía no tiene acceso con el nuevo sistema: escribe una contraseña para activarlo.");
    }
    if (!password) { password = passwordTemporal(); passwordGenerada = password; }
    try {
      await admin.auth().createUser({ uid: id, email, password, displayName: nombre });
    } catch (e) {
      if (e.code === "auth/email-already-exists") throw new HttpsError("already-exists", correo ? `El correo ${correo} ya lo usa otro usuario.` : `Ya existe otro usuario con el ID "${id}" (las mayúsculas no cuentan).`);
      throw e;
    }
  }

  const claims = { rol, campanas, nombre, loginId: id };
  if (JSON.stringify(claims).length > 900) throw new HttpsError("invalid-argument", "Demasiadas campañas para un solo usuario.");
  await admin.auth().setCustomUserClaims(id, claims);

  const perfil = { nombre, rol, "campaña": campanas, password: FieldValue.delete() };
  if (!soloSiNuevoPassword || correo) perfil.correo = correo || FieldValue.delete();
  if (datos.firma !== undefined) perfil.firma = String(datos.firma || "");
  if (datos.firma_img !== undefined) perfil.firma_img = safeUrl(datos.firma_img);
  await db.doc(`Usuarios/${id}`).set(perfil, { merge: true });

  return { id, creado: !existente, passwordGenerada };
}

exports.gestionarUsuario = onCall(async (request) => {
  const t = requireAuth(request);
  const llamanteEsAdmin = esAdminRol(t.rol);
  if (!(await tieneModulo(t.rol, "1"))) throw new HttpsError("permission-denied", "No tienes acceso al módulo de usuarios.");
  const datos = request.data || {};

  if (datos.accion === "guardar") {
    const r = await guardarUsuario(datos, llamanteEsAdmin);
    logger.info("Usuario guardado", { por: t.loginId, id: r.id, creado: r.creado });
    return { ok: true, creado: r.creado };
  }

  if (datos.accion === "eliminar") {
    const id = String(datos.id || "").trim();
    if (!ID_VALIDO.test(id)) throw new HttpsError("invalid-argument", "ID inválido.");
    if (id === t.loginId) throw new HttpsError("failed-precondition", "No puedes eliminar tu propio usuario.");
    let objetivo = null;
    try { objetivo = await admin.auth().getUser(id); } catch (e) { if (e.code !== "auth/user-not-found") throw e; }
    const perfil = await db.doc(`Usuarios/${id}`).get();
    const rolObjetivo = objetivo?.customClaims?.rol || (perfil.exists ? perfil.data().rol : "");
    if (esAdminRol(rolObjetivo) && !llamanteEsAdmin) throw new HttpsError("permission-denied", "No puedes eliminar a un administrador.");
    if (objetivo) await admin.auth().deleteUser(id);
    await db.doc(`Usuarios/${id}`).delete();
    logger.info("Usuario eliminado", { por: t.loginId, id });
    return { ok: true };
  }

  if (datos.accion === "importar") {
    const filas = Array.isArray(datos.filas) ? datos.filas.slice(0, 500) : [];
    const creados = []; const errores = []; let actualizados = 0;
    for (const f of filas) {
      try {
        // En la importación nunca se cambia la contraseña de un usuario existente.
        const r = await guardarUsuario({ ...f, password: null }, llamanteEsAdmin, { soloSiNuevoPassword: true });
        if (r.creado) creados.push({ id: r.id, password: r.passwordGenerada }); else actualizados++;
      } catch (e) { errores.push({ id: f?.id, error: e.message }); }
    }
    logger.info("Importación de usuarios", { por: t.loginId, creados: creados.length, actualizados, errores: errores.length });
    return { creados, actualizados, errores };
  }

  throw new HttpsError("invalid-argument", "Acción desconocida.");
});


// ================================================================== PLANTILLAS DE CORREO
function htmlPago(d, general) {
  const b = { ...CUENTA_DEFECTO, ...(general.cuenta_bancaria || {}) };
  const metodo = d.pago_metodo || "AMBOS";
  // Varios links (ej. uno por servicio): un botón por monto.
  const lista = Array.isArray(d.pago_links) ? d.pago_links.filter((x) => safeUrl(x.link)) : [];
  const varios = lista.length > 1;
  const link = varios ? safeUrl(lista[0].link) : safeUrl(d.pago_link);
  const boton = (url, texto) => `<div style="text-align:center; margin:12px 0;"><a href="${esc(url)}" target="_blank" style="background-color:#059669; color:#ffffff; padding:12px 20px; text-decoration:none; border-radius:6px; font-weight:bold; display:inline-block;">${texto}</a></div>`;
  const btn = varios
    ? `<p style="text-align:center; color:#475569; margin:8px 0 0;">Realice un pago por cada enlace:</p>` + lista.map((x) => boton(safeUrl(x.link), `💳 PAGAR Q ${(Number(x.monto) || 0).toFixed(2)}${x.concepto ? ` · ${esc(x.concepto)}` : ""}`)).join("")
    : link ? boton(link, "💳 CLICK PARA PROCEDER AL PAGO EN LÍNEA") : "";
  const caja = `<div style="background-color:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:15px; margin:15px 0; text-align:center; color:#1e293b; font-size:13px;"><p style="margin:0 0 5px 0;"><b>Banco:</b> ${esc(b.banco)}</p><p style="margin:0 0 5px 0;"><b>Tipo:</b> ${esc(b.tipo)}</p><p style="margin:0 0 5px 0;"><b>Cuenta:</b> ${esc(b.numero)}</p><p style="margin:0;"><b>A nombre de:</b> ${esc(b.titular)}</p></div>`;
  const titulo = (t, extra = "") => `<div style="text-align:center; font-weight:bold; color:#002244;${extra}">${t}</div>`;

  if (general.neonet_habilitado === false && metodo !== "TRANSFERENCIA") {
    const alt = general.neonet_mensaje_alterno || "El Link de Pago no está disponible por el momento.";
    let h = `<div style="background-color:#fef2f2; border:1px solid #f87171; border-radius:8px; padding:15px; text-align:center; color:#991b1b; font-weight:bold; margin:15px 0;">⚠️ ${escBr(alt)}</div>`;
    if (metodo === "AMBOS") h += caja;
    return h;
  }
  if (metodo === "TRANSFERENCIA") return titulo("Pago por transferencia:") + caja;
  // Sin enlace de pago no se muestra la opción de tarjeta vacía.
  if (!link && metodo === "AMBOS") return titulo("Pago por transferencia:") + caja;
  if (!link) return titulo("Link de Pago:") + `<p style="text-align:center; color:#475569;">En breve le compartiremos el Link de Pago.</p>`;
  if (metodo === "NEONET") return titulo("Link de Pago:") + btn;
  return titulo("Opción 1: Link de Pago:") + btn + titulo("Opción 2: Transferencia:", " margin-top:25px;") + caja;
}

// ---- Firma con imagen ----
// La imagen va DENTRO del correo (adjunto en línea, "cid"): el cliente la ve sin "descargar imágenes"
// y no depende de Google Drive. Las firmas de Drive (GIF animados de varios MB) tienen una versión
// liviana publicada con la app en /firmas/<id de Drive>.png.
const APP_URL = "https://gestiondecobros-st.vercel.app";
const CID_FIRMA = "firma@cobros-st";
const cacheFirmas = new Map();
async function bajarImagen(url, max) {
  const ctrl = new AbortController(); const tm = setTimeout(() => ctrl.abort(), 6000);
  try {
    const r = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
    if (!r.ok) return null;
    const tipo = String(r.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (!/^image\/(png|jpe?g|gif)$/.test(tipo)) return null;
    if (Number(r.headers.get("content-length") || 0) > max) return null;
    const content = Buffer.from(await r.arrayBuffer());
    return content.length && content.length <= max ? { content, contentType: tipo } : null;
  } catch (e) { return null; } finally { clearTimeout(tm); }
}
async function cargarFirma(perfil) {
  const url = safeUrl(perfil.firma_img); if (!url) return null;
  if (cacheFirmas.has(url)) return cacheFirmas.get(url);
  const driveId = (url.match(/[?&]id=([\w-]{10,})/) || url.match(/\/d\/([\w-]{10,})/) || [])[1];
  let img = driveId ? await bajarImagen(`${APP_URL}/firmas/${driveId}.png`, 400000) : null;
  if (!img) img = await bajarImagen(url, 600000); // enlace propio a una imagen liviana (PNG/JPG)
  if (img) cacheFirmas.set(url, img); else logger.warn("Firma sin imagen utilizable", { url });
  return img;
}
const adjuntosFirma = (img) => img ? [{ filename: `firma.${img.contentType.endsWith("png") ? "png" : img.contentType.endsWith("gif") ? "gif" : "jpg"}`, content: img.content, contentType: img.contentType, cid: CID_FIRMA, contentDisposition: "inline" }] : [];

function htmlFirma(agente, perfil) {
  const img = perfil.__firmaCid ? `cid:${CID_FIRMA}` : "";
  return `<div style="margin-top:25px; font-size:13px; color:#475569;"><p style="margin:0 0 5px 0;">Atentamente,</p><p style="margin:0; font-weight:bold; color:#002244; font-size:15px;">${esc(agente)}</p><p style="margin:2px 0 10px 0; color:#0077A3;">${escBr(perfil.firma || "Servicio Técnico")}</p>${img ? `<img src="${img}" width="400" height="80" style="display:block; width:400px; max-width:100%; height:auto; border:0;" alt="${esc(agente)}">` : ""}</div>`;
}

// Textos editables desde Ajustes → Correo al cliente (Configuracion/General.correo_textos).
// Deben coincidir con CORREO_TEXTOS_DEFECTO de public/index.html.
const CORREO_TEXTOS_DEFECTO = {
  encabezado: "DISTELSA · Servicio Técnico",
  introduccion: "Le compartimos el detalle de su orden de servicio {{orden}} para que pueda realizar el pago correspondiente.",
  instruccion: "Una vez realizado el pago, responda a este correo adjuntando su comprobante.",
  pie: "Responda a este correo para comunicarse con nosotros o enviar su comprobante de pago. Por favor no modifique el asunto, así identificamos su solicitud automáticamente.",
};
function textosCorreo(general) {
  const t = { ...CORREO_TEXTOS_DEFECTO };
  const g = (general && general.correo_textos) || {};
  for (const k of Object.keys(t)) if (typeof g[k] === "string" && g[k].trim()) t[k] = g[k].trim().slice(0, 600);
  return t;
}
// Escapa el texto y reemplaza {{cliente}} y {{solicitud}} (en negrita).
function conVariables(texto, vars) {
  return escBr(texto).replace(/\{\{(\w+)\}\}/g, (m, k) => (k in vars ? `<b>${esc(vars[k])}</b>` : m));
}

function envolver(contenido, textos = CORREO_TEXTOS_DEFECTO) {
  return `<!DOCTYPE html><html><body style="margin:0; padding:0; background:#f0f4f8;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8; padding:20px 0;"><tr><td align="center"><table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px; width:100%; background:#ffffff; border-radius:10px; overflow:hidden; font-family:Arial,Helvetica,sans-serif; color:#1e293b; font-size:14px; line-height:1.5;"><tr><td style="background:#002244; color:#ffffff; padding:18px 24px; font-size:18px; font-weight:bold;">${esc(textos.encabezado)}</td></tr><tr><td style="padding:24px;">${contenido}</td></tr><tr><td style="background:#f8fafc; padding:14px 24px; font-size:11px; color:#64748b; border-top:1px solid #e2e8f0;">${escBr(textos.pie)}</td></tr></table></td></tr></table></body></html>`;
}

// Descuento: el cliente ve subtotal y descuento; el motivo es interno y no va al correo.
function datosDescuento(d) {
  const m = Number(d.descuento?.monto) || 0;
  if (!(m > 0)) return null;
  const sub = Number(d.subtotal) || (Number(d.total) || 0) + m;
  const etiqueta = d.descuento?.tipo === "PORCENTAJE" ? `Descuento (${Number(d.descuento.valor) || 0}%)` : "Descuento";
  return { sub, m, etiqueta };
}

function htmlNuevoCobro(d, general, agente, perfil) {
  const c = d.cliente || {};
  const dsc = datosDescuento(d);
  const filaRes = (k, v, color) => `<tr><td colspan="3" style="padding:6px 8px; text-align:right; color:${color || "#475569"};">${k}</td><td style="padding:6px 8px; text-align:right; white-space:nowrap; color:${color || "#475569"};">${v}</td></tr>`;
  const lineasDescuento = dsc ? filaRes("Subtotal", `Q ${dsc.sub.toFixed(2)}`) + filaRes(esc(dsc.etiqueta), `− Q ${dsc.m.toFixed(2)}`, "#B45309") : "";
  const td = 'style="padding:8px; border-bottom:1px solid #e2e8f0; vertical-align:top;"';
  const filas = (d.servicios || []).map((s) => {
    const equipo = [s.producto, s.marca].filter(Boolean).join(" · ");
    return `<tr><td ${td}><b>${esc(s.tipo)}</b></td><td ${td}>${esc(equipo || "—")}${s.modelo ? `<br><span style="color:#64748b; font-size:12px;">Modelo: ${esc(s.modelo)}</span>` : ""}</td><td ${td}>${esc(s.detalle || "—")}</td><td ${td.replace('vertical-align:top;', 'vertical-align:top; text-align:right; white-space:nowrap;')}>Q ${(Number(s.precio) || 0).toFixed(2)}</td></tr>`;
  }).join("");
  // Datos del cliente: le confirman que el cobro es de su caso. Las notas internas y el temperamento nunca van al correo.
  const fila = (k, v) => (v ? `<tr><td style="padding:3px 10px 3px 0; color:#64748b; white-space:nowrap; vertical-align:top;">${k}</td><td style="padding:3px 0; color:#1e293b;">${esc(v)}</td></tr>` : "");
  const datosCliente = `<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:12px 14px; margin:15px 0; font-size:13px;"><div style="font-weight:bold; color:#002244; margin-bottom:6px;">Datos registrados</div><table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">${fila(String(d.orden_servicio || "").includes(",") ? "Órdenes de servicio" : "Orden de servicio", d.orden_servicio)}${fila("Nombre", c.contacto)}${fila("Teléfono", c.tel)}${fila("Correo", c.correo)}${fila("Dirección", c.dir)}</table></div>`;
  const fac = d.facturacion || {};
  const textos = textosCorreo(general);
  const vars = { cliente: c.contacto || "cliente", solicitud: d.orden_servicio || "", orden: d.orden_servicio || "" };
  return envolver(
    `<p style="margin-top:0;">Estimado(a) <b>${esc(c.contacto || "cliente")}</b>:</p>` +
    `<p>${conVariables(d.orden_servicio ? (String(d.orden_servicio).includes(",") ? textos.introduccion.replace(/su\s+orden\s+de\s+servicio/i, "sus órdenes de servicio") : textos.introduccion) : textos.introduccion.replace(/(?:su\s+)?orden\s+de\s+servicio\s+\{\{(?:orden|solicitud)\}\}/gi, "su solicitud").replace(/\s*\{\{(?:orden|solicitud)\}\}/g, ""), vars)}</p>` + datosCliente +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin:15px 0; font-size:13px;"><tr style="background:#e2e8f0; color:#002244;"><th align="left" style="padding:8px;">Servicio</th><th align="left" style="padding:8px;">Equipo</th><th align="left" style="padding:8px;">Detalle</th><th align="right" style="padding:8px;">Precio</th></tr>${filas}${lineasDescuento}<tr><td colspan="3" style="padding:10px 8px; text-align:right; font-weight:bold;">${dsc ? "TOTAL A PAGAR" : "TOTAL"}</td><td style="padding:10px 8px; text-align:right; font-weight:bold; font-size:16px; color:#002244; white-space:nowrap;">Q ${(Number(d.total) || 0).toFixed(2)}</td></tr></table>` +
    `<p style="font-size:12px; color:#475569; margin:0 0 15px 0;"><b>Facturar a:</b> ${esc(fac.nombre || "Consumidor Final")} · <b>NIT:</b> ${esc(fac.nit || "C/F")}</p>` +
    htmlPago(d, general) +
    `<p>${conVariables(textos.instruccion, vars)}</p>` +
    htmlFirma(agente, perfil),
    textos
  );
}

// Pago rápido: el cliente pidió la cuenta o el Link de Pago mientras espera en línea. Solo monto y formas de pago.
function htmlPagoRapido(d, general, agente, perfil) {
  const c = d.cliente || {};
  const sv = (d.servicios || [])[0] || {};
  const dscR = datosDescuento(d);
  const textos = textosCorreo(general);
  const fila = (k, v) => (v ? `<tr><td style="padding:3px 10px 3px 0; color:#64748b; white-space:nowrap; vertical-align:top;">${k}</td><td style="padding:3px 0; color:#1e293b;">${esc(v)}</td></tr>` : "");
  const resumen = `<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:14px; margin:15px 0; font-size:13px;"><table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">${fila("Nombre", c.contacto)}${fila("Teléfono", c.tel)}${fila(String(d.orden_servicio || "").includes(",") ? "Órdenes de servicio" : "Orden de servicio", d.orden_servicio)}${fila("Concepto", [sv.tipo, sv.detalle].filter(Boolean).join(" · "))}</table><div style="margin-top:10px; padding-top:10px; border-top:1px solid #e2e8f0; font-size:15px; color:#002244;">${dscR ? `<div style="font-size:13px; color:#475569;">Subtotal: Q ${dscR.sub.toFixed(2)}</div><div style="font-size:13px; color:#B45309; margin-bottom:4px;">${esc(dscR.etiqueta)}: − Q ${dscR.m.toFixed(2)}</div>` : ""}<b>Monto a pagar: Q ${(Number(d.total) || 0).toFixed(2)}</b></div></div>`;
  return envolver(
    `<p style="margin-top:0;">Estimado(a) <b>${esc(c.contacto || "cliente")}</b>:</p>` +
    `<p>Como lo solicitó, le compartimos los datos para realizar su pago.</p>` + resumen +
    htmlPago(d, general) +
    `<p>${conVariables(textos.instruccion, { cliente: c.contacto || "cliente", solicitud: d.orden_servicio || "", orden: d.orden_servicio || "" })}</p>` +
    htmlFirma(agente, perfil),
    textos
  );
}

function htmlRespuestaInterno(d, agente, mensaje, perfil) {
  const cliente = d.cliente?.contacto || "Cliente";
  let h = `<div style="background-color:#f1f5f9; padding:15px; border-radius:6px; border-left:4px solid #0077A3;">${escBr(mensaje)}</div>` + htmlFirma(agente, perfil) +
    `<hr style="border:0; border-bottom:1px solid #e2e8f0; margin:25px 0 15px;"><h4 style="color:#64748b; font-size:12px; text-transform:uppercase; margin:0 0 10px;">Historial${d.orden_servicio ? ` de la orden ${esc(d.orden_servicio)}` : ""}</h4>`;
  if (d.ultimo_mensaje_cliente && !MSG_VACIOS.includes(d.ultimo_mensaje_cliente)) {
    h += `<div style="margin-bottom:15px; border-left:2px solid #e2e8f0; padding-left:10px;"><p style="font-weight:bold; margin:0 0 3px; font-size:13px;">${esc(cliente)}</p><div style="color:#475569; font-size:13px;">${escBr(d.ultimo_mensaje_cliente)}</div></div>`;
  }
  [...(d.historial_respuestas || [])].reverse().forEach((m) => {
    if (m.agente === "SISTEMA") return;
    const esCliente = m.tipo === "cliente";
    if (!esCliente && !(m.tipo === "agente" && m.enviado_por_correo === true)) return;
    const quien = esCliente ? cliente : `${m.agente} (Soporte)`;
    const fecha = toDate(m.fecha); const fTxt = fecha ? fecha.toLocaleString("es-GT", { timeZone: "America/Guatemala" }) : "";
    h += `<div style="margin-bottom:15px; border-left:2px solid #e2e8f0; padding-left:10px;"><p style="font-weight:bold; margin:0 0 3px; font-size:13px; color:${esCliente ? "#475569" : "#0077A3"};">${esc(quien)} <span style="font-weight:normal; color:#94a3b8; font-size:11px;">${esc(fTxt)}</span></p><div style="color:#475569; font-size:13px;">${escBr(m.mensaje)}</div></div>`;
  });
  return h;
}
const htmlRespuesta = (d, agente, mensaje, perfil, general) => envolver(htmlRespuestaInterno(d, agente, mensaje, perfil), textosCorreo(general));





// ================================================================== MAKE (plan gratuito)
// Asunto editable en Ajustes → Correo al cliente (Configuracion/General.correo_asunto).
// Variables: {{solicitud}} {{orden}} {{cliente}} {{total}}. Debe coincidir con ASUNTO_DEFECTO de public/index.html.
const ASUNTO_DEFECTO = "Solicitud de pago - Orden {{orden}} - Distelsa Servicio Técnico";
function asuntoCobro(d, general) {
  const ticket = d.ticket || "";
  const plantilla = String((general && general.correo_asunto) || "").trim() || ASUNTO_DEFECTO;
  const orden = String(d.orden_servicio || "").trim();
  // El número interno ST no se muestra: {{solicitud}} (plantillas viejas) también muestra la orden.
  const vars = { solicitud: orden, orden, cliente: String(d.cliente?.contacto || "").trim(), total: `Q ${(Number(d.total) || 0).toFixed(2)}` };
  // Sin orden todavía: quita también la palabra que la acompaña ("Orden {{orden}}" → "").
  let base = plantilla;
  if (!vars.orden) base = base.replace(/(?:\b(?:orden(?:\s+de\s+servicio)?|OS|No\.?)\s*[:#]?\s*)?\{\{orden\}\}/gi, "");
  let a = base.replace(/\{\{(\w+)\}\}/g, (m, k) => (k in vars ? vars[k] : ""));
  // Limpia separadores que quedan sueltos cuando una variable viene vacía (ej. "OS  - ").
  a = a.replace(/[\r\n\t]+/g, " ").replace(/\(\s*\)|\[\s*\]/g, "").replace(/(\s*[-–|·:,]\s*){2,}/g, " - ").replace(/\s{2,}/g, " ").replace(/^[\s\-–|·:,]+|[\s\-–|·:,]+$/g, "").trim();
  if (!a) a = "Solicitud de pago - Distelsa Servicio Técnico";
  // En modo automático Make reconoce la respuesta por el número de solicitud: debe ir en el asunto.
  if (modoAutomatico(general) && ticket && !a.includes(ticket)) a += ` [${ticket}]`;
  return a.slice(0, 180);
}
const hashId = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 32);
const ZONA = "America/Guatemala";

// Créditos que gasta Make en cada evento (estimación para el contador del Dashboard).
// "copia": en modo automático, la copia (CC) de cada correo que regresa al Mailhook.
const CREDITOS = { envio: 2, copia: 1, respuesta: 2, comprobante: 3 };
const modoAutomatico = (general) => String(general?.modo_respuestas || "").toUpperCase() === "AUTOMATICO";
const LIMITE_MENSUAL = 1000;

function iguales(a, b) {
  const x = Buffer.from(String(a || "")); const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function mesActual() {
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: ZONA, year: "numeric", month: "2-digit" }).formatToParts(new Date());
  return `${p.find((x) => x.type === "year").value}-${p.find((x) => x.type === "month").value}`;
}

async function contarConsumo(evento, cantidad = 1) {
  const ref = db.doc(`Sistema/make_${mesActual()}`);
  await ref.set({
    [evento]: FieldValue.increment(cantidad),
    creditos_estimados: FieldValue.increment((CREDITOS[evento] || 0) * cantidad),
    limite: LIMITE_MENSUAL,
    actualizado: FieldValue.serverTimestamp(),
  }, { merge: true }).catch((e) => logger.warn("No se registró el consumo", { error: e.message }));
}

async function llamarMake(secreto, payload, etiqueta) {
  let res;
  try {
    res = await fetch(secreto.value(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, token: MAKE_TOKEN.value() }),
    });
  } catch (e) {
    logger.error(`No se pudo contactar a Make (${etiqueta})`, { error: e.message });
    throw new HttpsError("unavailable", "No se pudo contactar a Make.com.");
  }
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    logger.error(`Make rechazó la llamada (${etiqueta})`, { status: res.status, detalle: txt.slice(0, 300) });
    const msg = /operations|credits|quota|limit/i.test(txt)
      ? "Make se quedó sin créditos este mes."
      : `Make.com rechazó la llamada (HTTP ${res.status}).`;
    throw new HttpsError("unavailable", msg);
  }
}

// ------------------------------------------------------------------ ENVÍO
// El correo se arma completo (MIME) aquí y Make solo lo entrega a Outlook con "Send a MIME message".
// Así se pueden poner los encabezados In-Reply-To / References: la respuesta del agente queda
// en la MISMA conversación que el correo del cliente, usando solo el permiso de enviar.
async function armarMime({ para, asunto, html, responderA, copiaMake = false, adjuntos = [] }) {
  const idValido = /^<[^<>\s]+@[^<>\s]+>$/.test(String(responderA || "")) ? responderA : "";
  const soporte = SOPORTE_CORREO.value() || "soportest@distelsa.com.gt";
  // Solo en modo automático: el Mailhook va en copia para que Make lea la respuesta del cliente.
  const mailhook = copiaMake ? MAKE_MAILHOOK.value() : "";
  const opciones = {
    from: { name: "Soporte ST", address: soporte }, to: para, subject: asunto, html,
    replyTo: { name: "Soporte ST", address: soporte },
    // Modo automático: igual que el sistema anterior, el Mailhook va en copia. Con "Responder a todos"
    // la respuesta del cliente llega directo a Make (sin reenvío, que Distelsa bloquea) y a Soporte ST.
    ...(mailhook ? { cc: { name: "Soporte ST - Respuestas", address: mailhook } } : {}),
    messageId: `<${crypto.randomUUID()}@${(SOPORTE_CORREO.value() || "soportest@distelsa.com.gt").split("@")[1]}>`,
    text: htmlATexto(html, { wordwrap: 100, selectors: [{ selector: "img", format: "skip" }] }),
    textEncoding: "quoted-printable",
    ...(adjuntos.length ? { attachments: adjuntos } : {}),
  };
  if (idValido) { opciones.inReplyTo = idValido; opciones.references = [idValido]; }
  const buffer = await new MailComposer(opciones).compile().build();
  return buffer.toString("utf8").replace(/^Bcc:.*\r?\n/gim, "");
}

exports.enviarCorreoCobro = onCall({ secrets: [MAKE_WEBHOOK_ENVIO, MAKE_TOKEN] }, async (request) => {
  const t = requireAuth(request);
  const { ticketId, tipo } = request.data || {};
  if (!ticketId || !["NUEVO_COBRO", "NUEVA_RESPUESTA", "REENVIO"].includes(tipo)) throw new HttpsError("invalid-argument", "Datos incompletos.");

  const ref = db.doc(`Cobros/${ticketId}`);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "La solicitud no existe.");
  const d = snap.data();
  if (!esAdminRol(t.rol) && !(t.campanas || []).includes(d["campaña"])) throw new HttpsError("permission-denied", "La solicitud no es de tu campaña.");
  // REENVIO: se corrige el correo del cliente y se le manda otra vez la misma solicitud (sin abrir otra).
  const esReenvio = tipo === "REENVIO";
  const correoAnterior = String(d.cliente?.correo || "").trim();
  const correo = esReenvio ? String(request.data.correo || "").trim() : correoAnterior;
  if (!/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(correo)) throw new HttpsError(esReenvio ? "invalid-argument" : "failed-precondition", esReenvio ? "El correo nuevo no es válido." : "La solicitud no tiene un correo válido.");
  if (esReenvio && ["ANULADO", "PAUSADO"].includes(d.estatus)) throw new HttpsError("failed-precondition", "Esta solicitud está pausada o anulada; no se puede reenviar.");
  const motivoReenvio = String(request.data.motivo || "").trim().slice(0, 120);

  const [perfilSnap, generalSnap] = await Promise.all([db.doc(`Usuarios/${t.loginId}`).get(), db.doc("Configuracion/General").get()]);
  const perfil = perfilSnap.exists ? perfilSnap.data() : {};
  const general = generalSnap.exists ? generalSnap.data() : {};
  const imgFirma = await cargarFirma(perfil);
  perfil.__firmaCid = !!imgFirma;
  const adjuntos = adjuntosFirma(imgFirma);
  // El administrador puede pausar los correos desde Ajustes → Aviso y canales.
  if (general.correo_habilitado === false) throw new HttpsError("failed-precondition", "El envío por correo está pausado por el administrador.");
  const agente = t.nombre || t.loginId;
  const ticket = d.ticket || ticketId;
  const copiaMake = modoAutomatico(general);
  const contarEnvio = async () => { await contarConsumo("envio"); if (copiaMake) await contarConsumo("copia"); };

  if (esReenvio) {
    // Mismo contenido y asunto que el envío original, al correo corregido. No cambia quién lo envió (productividad).
    const asunto = d.correo_asunto || asuntoCobro({ ...d, ticket }, general);
    const dd = { ...d, ticket, cliente: { ...(d.cliente || {}), correo } };
    const mime = await armarMime({ para: correo, asunto, html: (d.tipo_cobro === "RAPIDO" ? htmlPagoRapido : htmlNuevoCobro)(dd, general, agente, perfil), copiaMake, adjuntos });
    await llamarMake(MAKE_WEBHOOK_ENVIO, { ticket, correo, asunto, mime }, "reenvío");
    await db.runTransaction(async (tx) => {
      const actual = (await tx.get(ref)).data() || {};
      const hist = [...(actual.historial_respuestas || [])];
      const cambio = correoAnterior.toLowerCase() !== correo.toLowerCase() ? ` (antes: ${correoAnterior || "sin correo"})` : "";
      hist.push({ tipo: "agente", fecha: new Date().toISOString(), agente, mensaje: `✉️ Solicitud reenviada por correo a ${correo}${cambio}.${motivoReenvio ? `\nMotivo: ${motivoReenvio}` : ""}`, enviado_por_correo: false });
      const act = {
        "cliente.correo": correo, correo_asunto: asunto, historial_respuestas: hist,
        reenviado_por: agente, reenviado_en: FieldValue.serverTimestamp(), envios_correo: FieldValue.increment(1),
        ultima_actividad: FieldValue.serverTimestamp(), actualizado_por: agente, fecha_actualizacion: FieldValue.serverTimestamp(),
      };
      if (actual.estatus === "ERROR EN ENVÍO") act.estatus = "ENVIADO";
      if (!actual.correo_enviado_en) act.correo_enviado_en = FieldValue.serverTimestamp();
      tx.update(ref, act);
    });
    await contarEnvio();
    logger.info("Solicitud reenviada", { ticket, por: t.loginId, cambioCorreo: correoAnterior !== correo });
    return { ok: true };
  }

  if (tipo === "NUEVO_COBRO") {
    const asunto = asuntoCobro({ ...d, ticket }, general);
    const mime = await armarMime({ para: correo, asunto, html: (d.tipo_cobro === "RAPIDO" ? htmlPagoRapido : htmlNuevoCobro)({ ...d, ticket }, general, agente, perfil), copiaMake, adjuntos });
    await llamarMake(MAKE_WEBHOOK_ENVIO, { ticket, correo, asunto, mime }, "envío");
    // Registro de quién envió (para el Dashboard de productividad).
    await ref.update({
      correo_asunto: asunto,
      correo_enviado_en: FieldValue.serverTimestamp(), enviado_en: FieldValue.serverTimestamp(),
      enviado_por: agente, enviado_por_id: t.loginId, canal_envio: "Correo", envios_correo: FieldValue.increment(1),
    });
    await contarEnvio();
    logger.info("Cobro enviado a Make", { ticket, por: t.loginId });
    return { ok: true };
  }

  const mensaje = String(request.data.mensaje || "").trim();
  if (!mensaje) throw new HttpsError("invalid-argument", "El mensaje está vacío.");
  if (mensaje.length > 5000) throw new HttpsError("invalid-argument", "El mensaje es demasiado largo (máx. 5000 caracteres).");

  // Si el cliente ya escribió, se RESPONDE sobre su último correo (misma conversación en Outlook).
  // Si no, se envía un correo nuevo con el historial.
  const responderA = String(d.ultimo_correo_cliente_msgid || "");
  const html = responderA
    ? `<div style="font-family:Arial,Helvetica,sans-serif; font-size:14px; color:#1e293b;">${escBr(mensaje)}${htmlFirma(agente, perfil)}</div>`
    : htmlRespuesta({ ...d, ticket }, agente, mensaje, perfil, general);
  // Usa el asunto con que se envió el cobro, para que quede en la misma conversación del cliente.
  const asunto = "RE: " + (d.correo_asunto || asuntoCobro({ ...d, ticket }, general));
  const mime = await armarMime({ para: correo, asunto, html, responderA, copiaMake, adjuntos });
  await llamarMake(MAKE_WEBHOOK_ENVIO, { ticket, correo, asunto, mime }, "envío");
  await contarEnvio();
  await db.runTransaction(async (tx) => {
    const actual = (await tx.get(ref)).data() || {};
    const hist = [...(actual.historial_respuestas || [])];
    const ahora = new Date().toISOString();
    if (actual.ultimo_mensaje_cliente && !MSG_VACIOS.includes(actual.ultimo_mensaje_cliente)) hist.push({ tipo: "cliente", fecha: ahora, mensaje: actual.ultimo_mensaje_cliente });
    hist.push({ tipo: "agente", fecha: ahora, agente, mensaje, enviado_por_correo: true });
    tx.update(ref, { historial_respuestas: hist, ultimo_mensaje_cliente: "Sin mensaje reciente", nueva_respuesta_cliente: false, ultima_actividad: FieldValue.serverTimestamp(), alerta_sla_creada: false });
  });
  return { ok: true };
});

// ------------------------------------------------------------------ ENTRADA DESDE MAKE
// Deja solo lo que escribió el cliente: corta en la cadena citada.
const ES_ENCABEZADO = /^(De|From|Enviado(?: el)?|Sent|Fecha|Date|Para|To|CC|Cc|CCO|Asunto|Subject|Importancia|Importance)\s*:/i;
const ES_SEPARADOR = /^(_{8,}|-{2,}\s*(Original Message|Mensaje original|Forwarded message|Mensaje reenviado)\s*-*|-{5,})$/i;

// Si el correo llegó REENVIADO (regla de Outlook "Reenviar a"), quita el encabezado del reenvío
// y devuelve el remitente original. Si llegó redirigido, no cambia nada.
function quitarReenvio(texto) {
  const lineas = String(texto || "").replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lineas.length && (!lineas[i].trim() || ES_SEPARADOR.test(lineas[i].trim()))) i++;
  if (i >= lineas.length || !/^(De|From)\s*:/i.test(lineas[i].trim())) return { texto: lineas.join("\n"), remitente: "" };
  const m = lineas[i].match(/[\w.+-]+@[\w-]+\.[\w.-]+/);
  while (i < lineas.length && (ES_ENCABEZADO.test(lineas[i].trim()) || !lineas[i].trim())) i++;
  return { texto: lineas.slice(i).join("\n"), remitente: m ? m[0].toLowerCase() : "" };
}

function textoNuevo(texto) {
  const lineas = String(texto || "").replace(/\r\n/g, "\n").split("\n");
  const fin = lineas.findIndex((l) => {
    const s = l.trim();
    return /^(De|From|Enviado el|Sent):\s/i.test(s)
      || ES_SEPARADOR.test(s)
      || /^(El|On)\s.+(escribió|wrote):\s*$/i.test(s)
      || /^>/.test(s);
  });
  const util = fin >= 0 ? lineas.slice(0, fin) : lineas;
  while (util.length && /^\s*([-_=*~]{3,}\s*)?$/.test(util[util.length - 1])) util.pop();   // separadores sueltos al final
  return util.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

// POST JSON con:
//   token         el MAKE_TOKEN
//   mensaje_id    Message-ID del correo (para no registrarlo dos veces y responder en el mismo hilo)
//   ticket        asunto del correo (se busca ST-######)
//   html | mensaje  cuerpo del correo (HTML o texto)
//   remitente     correo del cliente
//   comprobantes  lista de enlaces de Google Drive (opcional)
exports.recibirRespuestaCliente = onRequest({ secrets: [MAKE_TOKEN], cors: false }, async (req, res) => {
  try {
    if (req.method !== "POST") { res.status(405).send("Método no permitido"); return; }
    const body = req.body || {};
    if (!iguales(req.get("x-make-token") || body.token, MAKE_TOKEN.value())) { res.status(401).send("No autorizado"); return; }

    const match = String(body.ticket || "").match(/ST-\d{6}/i);
    if (!match) { res.json({ ok: true, resultado: "sin-ticket" }); return; }
    const ticket = match[0].toUpperCase();

    // Con el Mailhook en copia, Make también recibe los correos que envía Soporte ST
    // (cobros y respuestas del agente). Esos no son respuestas del cliente: se ignoran.
    const soporte = (SOPORTE_CORREO.value() || "soportest@distelsa.com.gt").toLowerCase();
    if (String(body.remitente || "").toLowerCase().includes(soporte)) { res.json({ ok: true, resultado: "propio" }); return; }

    const marca = db.doc(`CorreosProcesados/${hashId(body.mensaje_id || `${body.ticket}|${body.remitente}|${body.mensaje || body.html}`)}`);
    try { await marca.create({ ticket, procesado: FieldValue.serverTimestamp() }); }
    catch (e) { if (e.code === 6 || /already exists/i.test(e.message)) { res.json({ ok: true, resultado: "repetido" }); return; } throw e; }

    try {
      const ref = db.doc(`Cobros/${ticket}`);
      const snap = await ref.get();
      if (!snap.exists) { await marca.set({ estado: "ticket-inexistente" }, { merge: true }); res.json({ ok: true, resultado: "ticket-inexistente" }); return; }
      const d = snap.data();

      const plano = body.mensaje ? String(body.mensaje) : htmlATexto(String(body.html || ""), { wordwrap: false, selectors: [{ selector: "img", format: "skip" }, { selector: "a", options: { ignoreHref: true } }] });
      const reenvio = quitarReenvio(plano);
      let texto = textoNuevo(reenvio.texto).slice(0, 5000);
      const de = (reenvio.remitente || String(body.remitente || "")).toLowerCase().trim();
      const correoCliente = String(d.cliente?.correo || "").toLowerCase();
      if (texto && de && correoCliente && de !== correoCliente) texto = `[Enviado desde ${de}]\n${texto}`;
      let lista = body.comprobantes;
      if (typeof lista === "string") lista = lista.split(",");
      const comprobantes = (Array.isArray(lista) ? lista : []).map((u) => safeUrl(u)).filter(Boolean).slice(0, 20);
      if (!texto && comprobantes.length === 0) { await marca.set({ estado: "vacio" }, { merge: true }); res.json({ ok: true, resultado: "vacio" }); return; }

      const cambios = { ultima_actividad: FieldValue.serverTimestamp(), alerta_sla_creada: false, nueva_respuesta_cliente: true };
      if (!d.primera_respuesta_en) cambios.primera_respuesta_en = FieldValue.serverTimestamp();
      // Message-ID del correo del cliente: permite que el agente responda en la misma conversación.
      const msgid = String(body.message_id || body.mensaje_id || "").trim();
      if (/^<?[^<>\s]+@[^<>\s]+>?$/.test(msgid) && msgid.length < 400 && !/-adj-/.test(msgid)) cambios.ultimo_correo_cliente_msgid = msgid.startsWith("<") ? msgid : `<${msgid}>`;
      const pendiente = d.nueva_respuesta_cliente && d.ultimo_mensaje_cliente && !MSG_VACIOS.includes(d.ultimo_mensaje_cliente);
      if (texto) cambios.ultimo_mensaje_cliente = ((pendiente ? d.ultimo_mensaje_cliente + "\n\n---\n\n" : "") + texto).slice(0, 50000);
      else if (!pendiente) cambios.ultimo_mensaje_cliente = `[El cliente envió ${comprobantes.length} archivo(s) adjunto(s)]`;

      const catalogos = (await db.doc("Configuracion/Catalogos").get()).data() || {};
      const motor = motorDe(d.estatus, catalogos);
      if (comprobantes.length) {
        const previos = typeof d.comprobantes === "string" ? d.comprobantes.split(",").map((s) => s.trim()).filter(Boolean) : (Array.isArray(d.comprobantes) ? d.comprobantes : []);
        cambios.comprobantes = [...new Set([...previos, ...comprobantes])];
        if (motor !== "EXITO" && motor !== "INACTIVO") cambios.estatus = "COMPROBANTE RECIBIDO";
        if (!d.comprobante_en) cambios.comprobante_en = FieldValue.serverTimestamp();
      } else if (d.estatus === "ENVIADO") {
        cambios.estatus = "RECIBIDO";
      }
      await ref.update(cambios);
      await db.collection("Notificaciones").add({
        tipo: "SISTEMA", subtipo: comprobantes.length ? "COMPROBANTE" : "NUEVA_RESPUESTA", remitente: "SISTEMA CRM",
        destinatario: d.agente || "", "campaña": d["campaña"] || "", ticket,
        mensaje: comprobantes.length ? `El cliente envió ${comprobantes.length} comprobante(s).` : "El cliente respondió por correo.",
        fecha: new Date().toISOString(), leido: false,
      });
      await marca.set({ estado: "ok", comprobantes: comprobantes.length }, { merge: true });
      await contarConsumo("respuesta");
      if (comprobantes.length) await contarConsumo("comprobante", comprobantes.length);
      res.json({ ok: true, resultado: "ok", ticket, estatus: cambios.estatus || d.estatus });
    } catch (e) {
      await marca.delete().catch(() => {});
      throw e;
    }
  } catch (e) {
    logger.error("recibirRespuestaCliente", { error: e.message });
    res.status(500).send("Error interno");
  }
});

// ================================================================== SLA
// Configuracion/General.revision_turnos = { "0": [nombres] (domingo) … "6": [nombres] (sábado) }
// Configuracion/Turno = { fecha: "AAAA-MM-DD", revisores: [{ id, nombre }] } (tomado desde la Bandeja)
function revisoresDeHoy(general, turno = {}) {
  const dia = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[new Intl.DateTimeFormat("en-US", { timeZone: ZONA, weekday: "short" }).format(new Date())];
  const hoy = new Intl.DateTimeFormat("en-CA", { timeZone: ZONA }).format(new Date());
  const fijos = (general.revision_turnos || {})[String(dia)];
  const tomados = turno.fecha === hoy && Array.isArray(turno.revisores) ? turno.revisores.map((r) => r && r.nombre) : [];
  return [...new Set([...(Array.isArray(fijos) ? fijos : []), ...tomados].map((x) => String(x || "").trim()).filter(Boolean))].slice(0, 10);
}
// Corre en el servidor cada 15 min. Reemplaza la lógica que antes corría en
// CADA navegador abierto y generaba alertas duplicadas.
exports.revisarSLA = onSchedule({ schedule: "every 15 minutes", timeZone: "America/Guatemala" }, async () => {
  const [generalSnap, catSnap] = await Promise.all([db.doc("Configuracion/General").get(), db.doc("Configuracion/Catalogos").get()]);
  const slaHoras = Number(generalSnap.data()?.sla_horas) || 24;
  const catalogos = catSnap.data() || {};
  const limite = Date.now() - slaHoras * 3600 * 1000;
  // Persona(s) de turno para revisar respuestas hoy (Ajustes → Respuestas y revisión).
  const turnoSnap = await db.doc("Configuracion/Turno").get();
  const revisores = revisoresDeHoy(generalSnap.data() || {}, turnoSnap.exists ? turnoSnap.data() : {});

  const pendientes = await db.collection("Cobros").where("alerta_sla_creada", "==", false).get();
  let lote = db.batch(); let ops = 0; let alertas = 0;
  for (const docSnap of pendientes.docs) {
    const d = docSnap.data();
    const motor = motorDe(d.estatus, catalogos);
    if (motor === "EXITO" || motor === "INACTIVO") continue;
    const actividad = toDate(d.ultima_actividad) || toDate(d.fecha);
    if (!actividad || actividad.getTime() > limite) continue;

    lote.update(docSnap.ref, { alerta_sla_creada: true });
    lote.set(db.collection("Notificaciones").doc(), {
      tipo: "SISTEMA", subtipo: "ATRASO", remitente: "SISTEMA CRM", destinatario: d.agente || "",
      "campaña": d["campaña"] || "", ticket: d.ticket || docSnap.id,
      mensaje: `Sin actividad por más de ${slaHoras} h.`, fecha: new Date().toISOString(), leido: false,
    });
    ops += 2; alertas++;
    // Si sigue esperando respuesta del cliente, avisa también a quien revisa el correo hoy.
    if (["ENVIADO", "RECIBIDO"].includes(d.estatus)) {
      for (const r of revisores) {
        if (r === d.agente) continue;
        lote.set(db.collection("Notificaciones").doc(), {
          tipo: "SISTEMA", subtipo: "ATRASO", remitente: "SISTEMA CRM", destinatario: r,
          "campaña": d["campaña"] || "", ticket: d.ticket || docSnap.id,
          mensaje: `Revisa en Soporte ST si el cliente respondió (sin actividad por más de ${slaHoras} h).`, fecha: new Date().toISOString(), leido: false,
        });
        ops++;
      }
    }
    if (ops >= 400) { await lote.commit(); lote = db.batch(); ops = 0; }
  }
  if (ops > 0) await lote.commit();
  logger.info("revisarSLA", { revisadas: pendientes.size, alertas });
});

