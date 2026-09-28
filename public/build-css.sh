#!/bin/sh
# Rebuilds static/tailwind.css from the Tailwind classes used in templates/.
# Run it after adding or changing Tailwind classes in a template, then commit
# the regenerated file (the Docker image serves it as-is; no Node needed).
#
# Needs the Tailwind v3.4 standalone CLI, same version the site used to load
# from cdn.tailwindcss.com: https://github.com/tailwindlabs/tailwindcss/releases/tag/v3.4.17
# (put it on PATH as `tailwindcss`, or pass its path as TAILWIND=...).
set -eu
cd "$(dirname "$0")"
"${TAILWIND:-tailwindcss}" -c tailwind.config.js -i static/src/tailwind.in.css -o static/tailwind.css --minify
