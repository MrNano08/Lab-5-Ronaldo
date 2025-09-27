// UNA - utilidades de validación y saneamiento para el chat.
// Objetivos:
//  - Validar y sanear mensajes para prevenir XSS/inyecciones.
//  - Detectar URLs válidas de imágenes o videos (http/https) y clasificarlas.
//  - Exponer 'validarMensaje' y alias 'validateMessage' para compatibilidad.

const URL_RE = /(https?:\/\/[^\s<>"']+)/gi;

// Colores permitidos (nombres CSS simples) o #RRGGBB/#RGB
const COLOR_HEX_RE = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;
const COLOR_NAME_RE = /^(?:black|white|red|green|blue|yellow|purple|orange|gray|grey|silver|maroon|olive|lime|aqua|teal|navy|fuchsia|cyan|magenta)$/i;

// Extensiones aceptadas
const IMG_EXT_RE = /\.(?:png|jpe?g|gif|webp|avif|svg)(?:\?.*)?$/i;
const VID_EXT_RE = /\.(?:mp4|webm|ogg|ogv|mov|m4v)(?:\?.*)?$/i;

// Patrones de proveedores
const YT_WATCH_RE = /^https?:\/\/(?:www\.)?youtube\.com\/watch\?v=([\w-]{11})/i;
const YT_SHORT_RE = /^https?:\/\/(?:www\.)?youtu\.be\/([\w-]{11})/i;
const VIMEO_RE    = /^https?:\/\/(?:www\.)?vimeo\.com\/(\d{6,12})/i;

// ---- Utilidades de saneamiento (sin dependencias externas) ----

/** Escapa caracteres básicos para renderizar como texto (no HTML). */
function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Elimina etiquetas <script> y manejadores on* (por si el front los dejara pasar). */
function stripScriptsAndEventHandlers(input) {
  let s = String(input ?? "");
  // eliminar <script ...>...</script>
  s = s.replace(/<\s*script\b[^>]*>([\s\S]*?)<\s*\/\s*script\s*>/gi, "");
  // neutralizar atributos on*="..."
  s = s.replace(/\son\w+\s*=\s*"(.*?)"/gi, "");
  s = s.replace(/\son\w+\s*=\s*'(.*?)'/gi, "");
  s = s.replace(/\son\w+\s*=\s*[^>\s]+/gi, "");
  // bloquear javascript: en URLs incrustadas por si acaso
  s = s.replace(/javascript:/gi, "");
  return s;
}

/** Permite solo colores seguros (hex o nombre CSS simple). */
function sanitizeColor(c) {
  if (!c) return "#000000";
  const s = String(c).trim();
  if (COLOR_HEX_RE.test(s)) return s;
  if (COLOR_NAME_RE.test(s)) return s.toLowerCase();
  // Fallback seguro
  return "#000000";
}

/** Detecta si una URL apunta a imagen válida (por extensión). */
function isImageUrl(u) {
  try {
    const url = new URL(u);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    return IMG_EXT_RE.test(url.pathname);
  } catch {
    return false;
  }
}

/** Detecta si una URL es un video de archivo (mp4/webm/ogg/mov...). */
function isVideoFileUrl(u) {
  try {
    const url = new URL(u);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    return VID_EXT_RE.test(url.pathname);
  } catch {
    return false;
  }
}

/** YouTube/Vimeo -> devuelve objeto con provider y embedUrl si aplica. */
function detectVideoProvider(u) {
  try {
    const url = new URL(u);
    const href = url.href;

    let m = href.match(YT_WATCH_RE) || href.match(YT_SHORT_RE);
    if (m) {
      const id = m[1];
      return { kind: "video", provider: "youtube", embedUrl: `https://www.youtube.com/embed/${id}`, url: href };
    }

    m = href.match(VIMEO_RE);
    if (m) {
      const id = m[1];
      return { kind: "video", provider: "vimeo", embedUrl: `https://player.vimeo.com/video/${id}`, url: href };
    }

    if (isVideoFileUrl(href)) {
      return { kind: "video", provider: "file", src: href, url: href };
    }

    return null;
  } catch {
    return null;
  }
}

/** Clasifica una URL como imagen o video (o null). */
function classifyUrl(u) {
  if (isImageUrl(u)) {
    return { kind: "image", src: u, url: u };
  }
  const prov = detectVideoProvider(u);
  if (prov) return prov;
  return null;
}

/** Extrae la primera URL http/https del texto. */
function findFirstHttpUrl(text) {
  const matches = String(text ?? "").match(URL_RE);
  if (!matches) return null;
  // Priorizar la primera
  const candidate = matches[0];
  try {
    const url = new URL(candidate);
    if (url.protocol === "http:" || url.protocol === "https:") {
      return url.href;
    }
  } catch {}
  return null;
}

/**
 * Valida y sanea el mensaje.
 * Entrada: string (JSON con { nombre, color, mensaje } o texto plano)
 * Salida: JSON.stringify con:
 *   { nombre, color, mensaje, kind?: 'image'|'video', url/src/embedUrl?, provider? }
 */
function validarMensaje(msg) {
  try {
    // 1) Parseo tolerante
    let obj;
    if (typeof msg === "string") {
      try { obj = JSON.parse(msg); }
      catch { obj = { mensaje: String(msg) }; }
    } else if (msg && typeof msg === "object") {
      obj = { ...msg };
    } else {
      obj = { mensaje: String(msg ?? "") };
    }

    // 2) Campos básicos
    const nombre = escapeHtml(stripScriptsAndEventHandlers(obj.nombre ?? "Anónimo"));
    const color  = sanitizeColor(obj.color);
    let texto    = String(obj.mensaje ?? "");

    // 3) Saneamiento fuerte del texto
    texto = stripScriptsAndEventHandlers(texto);
    // No permitimos HTML en el payload final del texto; irá como texto plano
    const textoEscapado = escapeHtml(texto);

    // 4) Detección de URL segura (solo http/https) y clasificación
    const firstUrl = findFirstHttpUrl(texto);
    let payload = { nombre, color, mensaje: textoEscapado };

    if (firstUrl) {
      const cls = classifyUrl(firstUrl);
      if (cls) {
        // Eliminamos la URL del mensaje para que quede como "caption"
        const caption = escapeHtml(texto.replace(firstUrl, "").trim());
        payload.mensaje = caption;
        if (cls.kind === "image") {
          payload.kind = "image";
          payload.src  = cls.src;
        } else if (cls.kind === "video") {
          payload.kind = "video";
          payload.provider = cls.provider;
          if (cls.embedUrl) payload.embedUrl = cls.embedUrl;
          if (cls.src)      payload.src      = cls.src;
        }
      }
      // Si hay URL pero no es válida (imagen/video), NO se adjunta
    }

    return JSON.stringify(payload);
  } catch (e) {
    console.log("Error processing message:", e);
    // Fallback ultra conservador
    return JSON.stringify({ nombre: "Anónimo", color: "#000000", mensaje: escapeHtml(String(msg ?? "")) });
  }
}

// --- API pública ---
module.exports = {
  // Compatibilidad con código anterior
  validateMessage: validarMensaje,
  validarMensaje,

  // Utilidades expuestas para pruebas
  is_valid_phone: function(phone) {
    // Validación simple de números, +, espacios, guiones y paréntesis
    const re = /^[+()\s\-.\d]{6,20}$/;
    return re.test(String(phone ?? ""));
  },
  is_image_url: isImageUrl,
  is_video_url: isVideoFileUrl,
  detect_video_provider: detectVideoProvider,
  escapeHtml,
  stripScriptsAndEventHandlers,
  sanitizeColor,
};
