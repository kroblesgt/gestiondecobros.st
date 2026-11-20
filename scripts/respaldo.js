/**
 * Respaldo completo de Firestore a un archivo JSON (incluye subcolecciones).
 * Uso en Google Cloud Shell, desde la carpeta scripts/:
 *   npm install
 *   node respaldo.js
 * Crea respaldo-firestore-AAAA-MM-DD-HHMM.json. Descárgalo y guárdalo en un lugar seguro:
 * contiene datos de clientes y, antes de migrar, las contraseñas de los usuarios.
 */
const admin = require("firebase-admin");
const fs = require("fs");
admin.initializeApp({ projectId: process.env.GOOGLE_CLOUD_PROJECT || "gestiondecobrosst" });
const db = admin.firestore();

const serializar = (v) => {
  if (v instanceof admin.firestore.Timestamp) return { __tipo: "timestamp", valor: v.toDate().toISOString() };
  if (v instanceof admin.firestore.GeoPoint) return { __tipo: "geopoint", lat: v.latitude, lng: v.longitude };
  if (v instanceof admin.firestore.DocumentReference) return { __tipo: "ref", ruta: v.path };
  if (Array.isArray(v)) return v.map(serializar);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, serializar(x)]));
  return v;
};

async function volcar(coleccion) {
  const salida = {};
  const snap = await coleccion.get();
  for (const d of snap.docs) {
    const subs = await d.ref.listCollections();
    salida[d.id] = { datos: serializar(d.data()) };
    if (subs.length) { salida[d.id].subcolecciones = {}; for (const s of subs) salida[d.id].subcolecciones[s.id] = await volcar(s); }
  }
  return salida;
}

(async () => {
  const resultado = { proyecto: "gestiondecobrosst", fecha: new Date().toISOString(), colecciones: {} };
  const cols = await db.listCollections();
  for (const c of cols) {
    resultado.colecciones[c.id] = await volcar(c);
    console.log(`✓ ${c.id}: ${Object.keys(resultado.colecciones[c.id]).length} documentos`);
  }
  const f = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Guatemala", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date()).replace(/[^\d]/g, "");
  const nombre = `respaldo-firestore-${f.slice(0, 4)}-${f.slice(4, 6)}-${f.slice(6, 8)}-${f.slice(8, 12)}.json`;
  fs.writeFileSync(nombre, JSON.stringify(resultado, null, 1), { mode: 0o600 });
  console.log(`\nListo: ${nombre} (${(fs.statSync(nombre).size / 1024).toFixed(0)} KB)`);
})().catch((e) => { console.error("Error:", e.message); process.exit(1); });
