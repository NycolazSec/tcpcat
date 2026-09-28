// Shared FR/EN toggle for every tcpcat.io page. Each page captures its own
// authored text via [data-i18n] and supplies its own translation table;
// this file only knows how to swap between "the text that's already in the
// page" and "the table it was handed".
//
// Which language shows first: an explicit choice (a click, remembered in
// localStorage) wins; otherwise the browser's own language picks it (French
// -> fr, anything else -> en), so a visitor sees the same language on every
// page regardless of which language that page happens to be written in.
// Pages that render part of their content in JS (e.g. /release) read
// TcpcatI18n.current() and listen for the "tcpcat:lang" event.
(function () {
  var storageKey = 'tcpcat-lang';
  var current = null;

  function initLangToggle(translations, opts) {
    opts = opts || {};
    var defaultLang = opts.defaultLang || 'fr';
    var otherLang = opts.otherLang || 'en';
    current = defaultLang;

    var original = {};
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      original[el.getAttribute('data-i18n')] = el.innerHTML;
    });

    function setLang(lang, persist) {
      document.documentElement.lang = lang;
      document.querySelectorAll('[data-i18n]').forEach(function (el) {
        var key = el.getAttribute('data-i18n');
        if (lang !== defaultLang && translations[key] !== undefined) {
          el.innerHTML = translations[key];
        } else if (original[key] !== undefined) {
          el.innerHTML = original[key];
        }
      });
      var a = document.getElementById('btn-' + defaultLang);
      var b = document.getElementById('btn-' + otherLang);
      if (a) a.setAttribute('aria-pressed', String(lang === defaultLang));
      if (b) b.setAttribute('aria-pressed', String(lang === otherLang));
      current = lang;
      if (persist) {
        try {
          localStorage.setItem(storageKey, lang);
        } catch (e) {
          /* private browsing / storage disabled — language just won't persist */
        }
      }
      document.dispatchEvent(new CustomEvent('tcpcat:lang', { detail: lang }));
    }

    [defaultLang, otherLang].forEach(function (lang) {
      var btn = document.getElementById('btn-' + lang);
      if (btn) btn.addEventListener('click', function () { setLang(lang, true); });
    });

    var saved = null;
    try {
      saved = localStorage.getItem(storageKey);
    } catch (e) {
      /* ignore */
    }
    var browser = ((navigator.languages && navigator.languages[0]) || navigator.language || '').toLowerCase();
    var detected = browser.indexOf('fr') === 0 ? 'fr' : 'en';
    var initial = (saved === defaultLang || saved === otherLang) ? saved : detected;
    if (initial !== defaultLang && initial === otherLang) {
      setLang(initial, false);
    }
  }

  window.TcpcatI18n = {
    init: initLangToggle,
    current: function () { return current; },
  };
})();
