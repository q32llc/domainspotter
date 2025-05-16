## Caching for Template-Driven Pages

Template-driven HTML pages (e.g. `/`, `/privacy`, `/terms`, and 404s) are served with Cloudflare-compatible cache headers:

- `Cache-Control: public, max-age=3600, stale-while-revalidate=3600, stale-if-error=86400`
    - Cache for 1 hour at the edge
    - If backend is down, Cloudflare will serve stale content for up to 1 day
    - Cloudflare will revalidate in the background
- Only applies to GET/HEAD requests for HTML pages (not API or static files)

No cache headers are set for API or static routes.
