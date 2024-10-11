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

use ParagonIE\ConstantTime\Base64;
use SoftCreatR\WSCCrypto\Crypto;

// Example: Creating and verifying a signed string

try {
    // Securely load the signature secret, e.g., from environment variables or a secure config file
    $signatureSecret = \getenv('SIGNATURE_SECRET') ?: '0123456789abcdeffedcba987654321001234567';
    $crypto = new Crypto($signatureSecret);

    // Constructing data for version 1
    $version = \pack('C', 1);
    $sessionId = \hex2bin('abcdefabcdefabcdefabcdefabcdefabcdefabcd'); // 20 bytes
    $timestep = \pack('C', 10);
    $data = $version . $sessionId . $timestep;

    // Generate signature
    $signature = $crypto->getSignature($data);

    // Encode the data
    $encodedData = Base64::encode($data);

    // Create the signed string
    $generatedSignedString = $signature . '-' . $encodedData;

    echo "Generated Signed String:\n" . $generatedSignedString . "\n";

    // Verify and parse the generated signed string
    $parsedGeneratedData = $crypto->parseSignedString($generatedSignedString);

    if ($parsedGeneratedData !== null) {
        echo "\nParsed Data from Generated Signed String:\n";
        \print_r($parsedGeneratedData);
    } else {
        echo "\nFailed to parse the generated signed string.\n";
    }
} catch (Exception $e) {
    // Handle exceptions gracefully
    \http_response_code(500);
    echo 'Error: ' . $e->getMessage();

    exit(1);
}
