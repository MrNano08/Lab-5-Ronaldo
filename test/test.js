const assert = require('assert');
const lib = require('../libs/unalib');

describe('una-lib: validaciones y clasificación de URLs', function () {

  describe('is_image_url', function () {
    it('acepta .png http', function () {
      assert.strictEqual(lib.is_image_url('http://example.com/a.png'), true);
    });
    it('acepta .jpg https', function () {
      assert.strictEqual(lib.is_image_url('https://cdn.site.org/pic.jpg?x=1'), true);
    });
    it('rechaza data: y javascript:', function () {
      assert.strictEqual(lib.is_image_url('javascript:alert(1)'), false);
      assert.strictEqual(lib.is_image_url('data:image/png;base64,AAAA'), false);
    });
  });

  describe('detect_video_provider', function () {
    it('detecta YouTube y genera embed', function () {
      const v = lib.detect_video_provider('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
      assert.ok(v && v.kind === 'video' && v.provider === 'youtube');
      assert.ok(v.embedUrl.includes('youtube.com/embed/'));
    });
    it('detecta Vimeo y genera embed', function () {
      const v = lib.detect_video_provider('https://vimeo.com/76979871');
      assert.ok(v && v.kind === 'video' && v.provider === 'vimeo');
      assert.ok(v.embedUrl.includes('player.vimeo.com/video/'));
    });
    it('acepta archivo mp4 directo', function () {
      const v = lib.detect_video_provider('https://files.site.com/clip.mp4');
      assert.ok(v && v.kind === 'video' && v.provider === 'file');
    });
  });

  describe('validarMensaje', function () {
    it('clasifica imagen y mantiene caption', function () {
      const raw = JSON.stringify({
        nombre: 'Ana <script>alert(1)</script>',
        color: '#ff0000',
        mensaje: 'mira esto https://example.com/foto.webp es genial'
      });
      const out = JSON.parse(lib.validarMensaje(raw));
      assert.strictEqual(out.kind, 'image');
      assert.strictEqual(out.src, 'https://example.com/foto.webp');
      assert.ok(out.nombre.includes('Ana'));            // saneado
      assert.ok(!out.nombre.includes('<script>'));      // sin script
      assert.strictEqual(out.mensaje.startsWith('mira esto'), true);
      assert.strictEqual(out.mensaje.includes('https://example.com/foto.webp'), false); // URL removida
    });

    it('clasifica video de YouTube', function () {
      const raw = JSON.stringify({
        nombre: 'Luis',
        color: 'blue',
        mensaje: 'vean https://youtu.be/dQw4w9WgXcQ porfa'
      });
      const out = JSON.parse(lib.validarMensaje(raw));
      assert.strictEqual(out.kind, 'video');
      assert.strictEqual(out.provider, 'youtube');
      assert.ok(out.embedUrl.includes('youtube.com/embed/'));
    });

    it('previene inyección de scripts', function () {
      const raw = JSON.stringify({
        nombre: 'pepe',
        color: '#00ff00',
        mensaje: '<img src=x onerror=alert(1)><script>alert(2)</script>hola'
      });
      const out = JSON.parse(lib.validarMensaje(raw));
      // No debe haber etiquetas script ni onerror
      assert.strictEqual(out.mensaje.includes('<script>'), false);
      assert.strictEqual(out.mensaje.includes('onerror'), false);
      // Mensaje queda como texto seguro escapado
      assert.ok(out.mensaje.includes('hola'));
    });
  });

});
