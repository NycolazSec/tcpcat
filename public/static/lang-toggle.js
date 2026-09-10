// Shared FR/EN toggle for every tcpcat.io page. Each page captures its own
// authored text via [data-i18n] and supplies its own translation table;
// this file only knows how to swap between "the text that's already in the
// page" and "the table it was handed" — and to remember the choice.
(function () {
  function initLangToggle(translations, opts) {
    opts = opts || {};
    var defaultLang = opts.defaultLang || 'fr';
    var otherLang = opts.otherLang || 'en';
    var storageKey = 'tcpcat-lang';

    var original = {};
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      original[el.getAttribute('data-i18n')] = el.innerHTML;
    });

    function buttons() {
      return {
        a: document.getElementById('btn-' + defaultLang),
        b: document.getElementById('btn-' + otherLang),
      };
    }

    function setLang(lang) {
      document.documentElement.lang = lang;
      document.querySelectorAll('[data-i18n]').forEach(function (el) {
        var key = el.getAttribute('data-i18n');
        if (lang !== defaultLang && translations[key] !== undefined) {
          el.innerHTML = translations[key];
        } else {
          el.innerHTML = original[key];
        }
      });
      var btn = buttons();
      if (btn.a) btn.a.setAttribute('aria-pressed', String(lang === defaultLang));
      if (btn.b) btn.b.setAttribute('aria-pressed', String(lang === otherLang));
      try {
        localStorage.setItem(storageKey, lang);
      } catch (e) {
        /* private browsing / storage disabled — language just won't persist */
      }
    }

    var btn = buttons();
    if (btn.a) btn.a.addEventListener('click', function () { setLang(defaultLang); });
    if (btn.b) btn.b.addEventListener('click', function () { setLang(otherLang); });

    var saved = null;
    try {
      saved = localStorage.getItem(storageKey);
    } catch (e) {
      /* ignore */
    }
    if (saved === defaultLang || saved === otherLang) {
      setLang(saved);
    }
  }

  window.TcpcatI18n = { init: initLangToggle };
})();
