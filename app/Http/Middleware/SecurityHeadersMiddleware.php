<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $isProd   = app()->environment('production');

        /**
         * ================================
         *  BASIC SECURITY HEADERS
         * ================================
         */
        if ($isProd) {
            // HSTS → hanya aktif di production
            // - Paksa browser selalu pakai HTTPS
            // - includeSubDomains = berlaku juga ke subdomain
            // - preload = eligible untuk preload list Chrome/Firefox
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }

        // Block sniffing MIME → cegah XSS/klikjacking dengan file palsu
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Old-school anti iframe hijack (legacy). 
        // Sebenarnya sudah di-cover CSP `frame-ancestors`, tapi ini aman buat browser lama.
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // Kebijakan referrer → kirim referrer hanya domain+origin (bukan full URL path) ke cross-origin.
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Header COOP/CORP → cegah side-channel attack (Spectre, dll.)
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');
        // $response->headers->set('Cross-Origin-Embedder-Policy', 'require-corp'); 
        // ⚠️ hati-hati kalau aplikasi embed resource dari luar.

        // Batasi izin fitur → defaultnya semua OFF
        $response->headers->set('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');

        /**
         * ================================
         *  CONTENT SECURITY POLICY (CSP)
         * ================================
         * - Development: longgar (allow localhost:5173 untuk Vite + inline)
         * - Production: ketat (no unsafe-inline, no unsafe-eval, kecuali style attribute)
         */
        if (app()->isLocal()) {
            // Host Vite dev server (default port 5173)
            $viteHttp = 'http://localhost:5173 http://127.0.0.1:5173';
            $viteWs   = 'ws://localhost:5173 ws://127.0.0.1:5173';

            $csp = ""
                // Semua default hanya dari domain sendiri
                . "default-src 'self'; "
                . "base-uri 'self'; "
                . "object-src 'none'; "
                . "frame-ancestors 'self'; "

                // Font dari self + fonts.bunny.net + data URI
                . "font-src 'self' https://fonts.bunny.net data:; "

                // Style: allow inline + Vite dev host + fonts CDN
                . "style-src 'self' 'unsafe-inline' https://fonts.bunny.net http: {$viteHttp}; "
                . "style-src-elem 'self' 'unsafe-inline' https://fonts.bunny.net http: {$viteHttp}; "

                // Script: allow unsafe-eval + blob: untuk Vite HMR
                . "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: http: {$viteHttp}; "
                . "script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' blob: http: {$viteHttp}; "

                // Connect: allow AJAX/WebSocket ke Vite + self
                . "connect-src 'self' {$viteHttp} {$viteWs} ws: wss:; "

                // Images: allow self + data URI + blob (misalnya file upload preview)
                . "img-src 'self' data: blob:; ";
        } else {
            // === STRICT PRODUCTION RULES ===
            $csp = ""
                . "default-src 'self'; "
                . "base-uri 'self'; "
                . "object-src 'none'; "
                . "frame-ancestors 'self'; "
                . "upgrade-insecure-requests; " // auto-upgrade http → https

                // Font dari self + fonts.bunny.net + data URI
                . "font-src 'self' https://fonts.bunny.net data:; "

                // Style: no <style> inline, tapi allow style attributes (style-src-attr)
                . "style-src 'self' https://fonts.bunny.net; "
                . "style-src-attr 'unsafe-inline'; "

                // Script: hanya dari self
                . "script-src 'self'; "

                // AJAX/fetch: hanya ke self
                . "connect-src 'self'; "

                // Images: allow self + data URI + blob (misalnya base64 img)
                . "img-src 'self' data: blob:; ";
        }

        /**
         * ================================
         *  REPORT ONLY MODE
         * ================================
         * - Gunakan ini saat testing: CSP error dilog tanpa blocking
         * - Aktifkan dengan .env → CSP_REPORT_ONLY=true
         */
        if (filter_var(env('CSP_REPORT_ONLY', false), FILTER_VALIDATE_BOOL)) {
            $response->headers->set('Content-Security-Policy-Report-Only', $csp);
        } else {
            $response->headers->set('Content-Security-Policy', $csp);
        }

        return $response;
    }
}
