/** Tailwind v3.4 config for tcpcat.io -- see build-css.sh. Only classes that
    appear in these files end up in static/tailwind.css, including classes
    written inside the inline FR/EN translation strings of each template. */
module.exports = {
  content: ['./templates/**/*.html', './static/**/*.js'],
  theme: { extend: {} },
  plugins: [],
};
