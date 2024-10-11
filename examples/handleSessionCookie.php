<?php

/**
 * Copyright (c) 2024, Sascha Greuel <hello@1-2.dev>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

require __DIR__ . '/../vendor/autoload.php';

use SoftCreatR\WSCCrypto\Crypto;

// Example: Parsing a signed string directly using a session cookie

try {
    // Securely load the signature secret, e.g., from environment variables or a secure config file
    $signatureSecret = \getenv('SIGNATURE_SECRET') ?: '0123456789abcdeffedcba987654321001234567';
    $crypto = new Crypto($signatureSecret);

    // Retrieve the signed session cookie
    $signedString = $_COOKIE['wsc_xyz123_user_session'] ?? null;

    if ($signedString) {
        $parsedData = $crypto->parseSignedString($signedString);

        if ($parsedData) {
            // Sanitize the session ID to prevent potential XSS attacks
            $sessionId = \htmlspecialchars($parsedData['sessionId'], \ENT_QUOTES, 'UTF-8');

            exit($sessionId);
        }

        // Invalid signature or malformed data
        \http_response_code(400);

        exit('Invalid session data.');
    }

    // No session cookie provided
    \http_response_code(401);

    exit('Session cookie not found.');
} catch (Exception $e) {
    // Handle exceptions gracefully
    \http_response_code(500);
    echo 'Error: ' . $e->getMessage();

    exit(1);
}
