<?php

/*
 * Copyright (c) 2024, Sascha Greuel <hello@1-2.dev> and Contributors
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

namespace SoftCreatR\WSCCrypto;

use InvalidArgumentException;
use LogicException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;
use RangeException;
use SensitiveParameter;

/**
 * Class Crypto
 *
 * Handles cryptographic operations such as signature generation and signed string parsing.
 *
 * @link https://github.com/WoltLab/WCF/blob/master/wcfsetup/install/files/lib/system/session/SessionHandler.class.php
 * @link https://github.com/WoltLab/WCF/blob/master/wcfsetup/install/files/lib/util/CryptoUtil.class.php
 */
final class Crypto
{
    /**
     * @var int Minimum length requirement for the signature secret.
     */
    private const SIGNATURE_SECRET_MIN_LENGTH = 15;

    /**
     * @var array Supported versions.
     */
    private const SUPPORTED_VERSIONS = [1];

    /**
     * Crypto constructor.
     *
     * @param string $signatureSecret Secret key for HMAC signature.
     *
     * @throws InvalidArgumentException If the signature secret is too short.
     */
    public function __construct(
        #[SensitiveParameter]
        private readonly string $signatureSecret
    ) {
        if (\mb_strlen($signatureSecret, '8bit') < self::SIGNATURE_SECRET_MIN_LENGTH) {
            throw new InvalidArgumentException(
                'SIGNATURE_SECRET is too short, must be at least ' . self::SIGNATURE_SECRET_MIN_LENGTH . ' bytes.'
            );
        }
    }

    /**
     * Generates a HMAC signature for a given value.
     *
     * @param string $value The value to sign.
     *
     * @return string The generated signature.
     */
    public function getSignature(string $value): string
    {
        return \hash_hmac('sha256', $value, $this->signatureSecret);
    }

    /**
     * Retrieves the value from a signed string if the signature is valid.
     *
     * @param string $signedString The signed string in the format 'signature-value'.
     *
     * @return string|null The original value if the signature is valid, null otherwise.
     */
    public function getValueFromSignedString(#[SensitiveParameter] string $signedString): ?string
    {
        $parts = \explode('-', $signedString, 2);

        if (\count($parts) !== 2) {
            return null;
        }

        [$signature, $encodedValue] = $parts;

        try {
            $value = Base64::decode($encodedValue);
        } catch (RangeException) {
            return null;
        }

        if (!\hash_equals($signature, $this->getSignature($value))) {
            return null;
        }

        return $value;
    }

    /**
     * Parses and retrieves cookie data from a provided signed string if valid.
     *
     * @param string $signedString The signed string in the format 'signature-value'.
     *
     * @return array|null Parsed data array or null if invalid.
     */
    public function parseSignedString(#[SensitiveParameter] string $signedString): ?array
    {
        $signedString = \urldecode($signedString);
        $cookieData = $this->getValueFromSignedString($signedString);

        if ($cookieData === null) {
            return null;
        }

        try {
            return $this->parseData($cookieData);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Parses the raw data string into structured data.
     *
     * @param string $value The raw data string.
     *
     * @return array Parsed data.
     *
     * @throws InvalidArgumentException If the data is invalid.
     */
    public function parseData(#[SensitiveParameter] string $value): array
    {
        $length = \mb_strlen($value, '8bit');

        if ($length < 1) {
            throw new InvalidArgumentException(\sprintf(
                'Expected at least 1 byte, %d given.',
                $length
            ));
        }

        $unpacked = \unpack('Cversion', $value);

        if ($unpacked === false || !isset($unpacked['version'])) {
            throw new InvalidArgumentException('Failed to unpack version from data.');
        }

        $version = $unpacked['version'];

        if (!\in_array($version, self::SUPPORTED_VERSIONS, true)) {
            throw new InvalidArgumentException(\sprintf(
                'Unknown version %d.',
                $version
            ));
        }

        return match ($version) {
            1 => $this->parseVersion1($value),
            default => throw new LogicException('Unhandled version.'),
        };
    }

    /**
     * Parses data for version 1.
     *
     * @param string $value The raw data string.
     *
     * @return array Parsed data including version, sessionId, and timestep.
     *
     * @throws InvalidArgumentException If the data length is incorrect.
     */
    private function parseVersion1(string $value): array
    {
        $expectedLength = 22;
        $actualLength = \mb_strlen($value, '8bit');

        if ($actualLength !== $expectedLength) {
            throw new InvalidArgumentException(\sprintf(
                'Expected exactly %d bytes, %d given.',
                $expectedLength,
                $actualLength
            ));
        }

        $data = \unpack('Cversion/a20sessionId/Ctimestep', $value);

        if ($data === false || !isset($data['version'], $data['sessionId'], $data['timestep'])) {
            throw new InvalidArgumentException('Failed to unpack data.');
        }

        // Encode sessionId as hexadecimal
        $data['sessionId'] = Hex::encode($data['sessionId']);

        return $data;
    }
}
