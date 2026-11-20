/**
 * Migra los usuarios de la colección "Usuarios" (contraseña en texto plano)
 * a Firebase Authentication con custom claims, y BORRA la contraseña de Firestore.
 *
 * Uso (desde la carpeta scripts/, en Google Cloud Shell):
 *   npm install
 *   node migrar-usuarios.js              -> SIMULACIÓN, no cambia nada
 *   node migrar-usuarios.js --ejecutar   -> aplica los cambios
 *
 * Cada usuario conserva su contraseña actual, salvo que tenga menos de 6
 * caracteres (mínimo de Firebase). A esos se les genera una temporal y se
 * listan en credenciales-temporales.csv. Entrega esas claves en privado y
 * BORRA el archivo después.
 *
 * Es seguro ejecutarlo más de una vez: los usuarios ya migrados se actualizan.
 */
const admin = require("firebase-admin");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const DOMINIO_LOGIN = "cobros-st.local"; // Debe coincidir con public/index.html y functions/index.js
const ID_VALIDO = /^[A-Za-z0-9._-]{2,64}$/;

// En Google Cloud Shell no hace falta archivo de clave: usa la sesión del usuario.
//   node migrar-usuarios.js              -> simulación
//   node migrar-usuarios.js --ejecutar   -> aplica
// En una computadora: node migrar-usuarios.js ./clave-servicio.json [--ejecutar]
const args = process.argv.slice(2);
const EJECUTAR = args.includes("--ejecutar");
const rutaClave = args.find((a) => a !== "--ejecutar");
if (rutaClave && !fs.existsSync(rutaClave)) { console.error(`No existe el archivo de clave: ${rutaClave}`); process.exit(1); }
admin.initializeApp(rutaClave
  ? { credential: admin.credential.cert(require(path.resolve(rutaClave))) }
  : { projectId: process.env.GOOGLE_CLOUD_PROJECT || "gestiondecobrosst" });
const db = admin.firestore();

function passwordTemporal() {
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  return Array.from(crypto.randomBytes(12), (b) => abc[b % abc.length]).join("");
}

(async () => {
  console.log(EJECUTAR ? "=== MODO EJECUCIÓN: se aplicarán cambios ===\n" : "=== SIMULACIÓN: no se cambia nada (agrega --ejecutar para aplicar) ===\n");

  const snap = await db.collection("Usuarios").get();
  const vistos = new Map();
  const temporales = [];
  let ok = 0, omitidos = 0, errores = 0;

  for (const d of snap.docs) {
    const id = d.id;
    const u = d.data();
    const nombre = String(u.nombre || id).trim();
    const rol = String(u.rol || "").trim().toUpperCase();
    const campanas = (Array.isArray(u["campaña"]) ? u["campaña"] : [u["campaña"]]).map((c) => String(c || "").trim()).filter(Boolean);

    if (!ID_VALIDO.test(id)) { console.warn(`✗ ${id}: ID con caracteres no permitidos. Créalo de nuevo desde la app con un ID válido.`); omitidos++; continue; }
    if (!rol) { console.warn(`✗ ${id}: no tiene rol. Asígnale uno en Firestore y vuelve a correr el script.`); omitidos++; continue; }
    const clave = id.toLowerCase();
    if (vistos.has(clave)) { console.warn(`✗ ${id}: choca con "${vistos.get(clave)}" (solo cambian mayúsculas). Renombra uno de los dos.`); omitidos++; continue; }
    vistos.set(clave, id);

    let password = typeof u.password === "string" ? u.password : "";
    let esTemporal = false;
    if (password.length < 6) { password = passwordTemporal(); esTemporal = true; }

    const email = `${clave}@${DOMINIO_LOGIN}`;
    const claims = { rol, campanas, nombre, loginId: id };
    const resumen = `${id.padEnd(20)} rol=${rol.padEnd(14)} campañas=[${campanas.join(", ")}]${esTemporal ? "  ⚠ contraseña temporal" : ""}`;

    if (!EJECUTAR) { console.log("• " + resumen); if (esTemporal) temporales.push({ id, password: "(se generará al ejecutar)" }); ok++; continue; }

    try {
      let existe = true;
      try { await admin.auth().getUser(id); } catch (e) { if (e.code === "auth/user-not-found") existe = false; else throw e; }
      if (existe) {
        const cambios = { email, displayName: nombre };
        if (u.password) cambios.password = password; // aún tenía contraseña en Firestore: se sincroniza
        await admin.auth().updateUser(id, cambios);
      } else {
        await admin.auth().createUser({ uid: id, email, password, displayName: nombre });
      }
      await admin.auth().setCustomUserClaims(id, claims);
      await d.ref.update({ password: admin.firestore.FieldValue.delete(), rol, "campaña": campanas, migrado_auth: new Date().toISOString() });
      if (esTemporal && (u.password !== undefined || !existe)) temporales.push({ id, password });
      console.log("✓ " + resumen);
      ok++;
    } catch (e) {
      console.error(`✗ ${id}: ${e.message}`);
      errores++;
    }
  }

  if (EJECUTAR && temporales.length > 0) {
    const csv = "ID,CONTRASEÑA_TEMPORAL\n" + temporales.map((t) => `${t.id},${t.password}`).join("\n");
    fs.writeFileSync("credenciales-temporales.csv", csv, { mode: 0o600 });
    console.log(`\n⚠ ${temporales.length} usuario(s) con contraseña temporal → credenciales-temporales.csv (bórralo después de entregarlas).`);
  }
  console.log(`\nResumen: ${ok} ${EJECUTAR ? "migrados" : "por migrar"}, ${omitidos} omitidos, ${errores} con error.`);
  if (!EJECUTAR) console.log("Si todo se ve bien, vuelve a correr con --ejecutar.");
  process.exit(errores > 0 ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
