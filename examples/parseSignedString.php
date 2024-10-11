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

// Example: Parsing a signed string directly

try {
    // Securely load the signature secret, e.g., from environment variables or a secure config file
    $signatureSecret = \getenv('SIGNATURE_SECRET') ?: '0123456789abcdeffedcba987654321001234567';
    $crypto = new Crypto($signatureSecret);

    $signedString = '58347755b81224ac6dc6e0636e1a02f6ed63d80bceb8f355664167c58c9f7d0f-AXZUMhABI0VniavN7/7cuph2VDIQCg==';
    $parsedData = $crypto->parseSignedString($signedString);

    if ($parsedData !== null) {
        // Successfully parsed signed string
        echo "Parsed Data from Provided Signed String:\n";
        \print_r($parsedData);
    } else {
        echo "No valid data found in the provided signed string.\n";
    }
} catch (Exception $e) {
    // Handle exceptions gracefully
    \http_response_code(500);
    echo 'Error: ' . $e->getMessage();

    exit(1);
}
