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

namespace SoftCreatR\WSCCrypto\Tests;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use PHPUnit\Framework\TestCase;
use SoftCreatR\WSCCrypto\Crypto;

/**
 * @covers \SoftCreatR\WSCCrypto\Crypto
 */
class CryptoTest extends TestCase
{
    private const SIGNATURE_SECRET = '0123456789abcdeffedcba987654321001234567';

    private Crypto $crypto;

    protected function setUp(): void
    {
        $this->crypto = new Crypto(self::SIGNATURE_SECRET);
    }

    public function testGetSignature(): void
    {
        $value = 'test_value';
        $signature = $this->crypto->getSignature($value);

        $this->assertIsString($signature);
        $this->assertEquals(64, \strlen($signature)); // SHA-256 hash in hex is 64 characters
    }

    public function testGetValueFromSignedStringValid(): void
    {
        $value = 'test_value';
        $signature = $this->crypto->getSignature($value);
        $encodedValue = Base64::encode($value);
        $signedString = $signature . '-' . $encodedValue;

        $result = $this->crypto->getValueFromSignedString($signedString);

        $this->assertEquals($value, $result);
    }

    public function testGetValueFromSignedStringInvalidSignature(): void
    {
        $value = 'test_value';
        $invalidSignature = 'invalidsignature1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
        $encodedValue = Base64::encode($value);
        $signedString = $invalidSignature . '-' . $encodedValue;

        $result = $this->crypto->getValueFromSignedString($signedString);

        $this->assertNull($result);
    }

    public function testGetValueFromSignedStringMalformedString(): void
    {
        $malformedSignedString = 'malformedstringwithoutseparator';

        $result = $this->crypto->getValueFromSignedString($malformedSignedString);

        $this->assertNull($result);
    }

    public function testGetValueFromSignedStringInvalidBase64(): void
    {
        $signature = $this->crypto->getSignature('test_value');
        $invalidBase64 = '!!!invalidbase64!!!';
        $signedString = $signature . '-' . $invalidBase64;

        $result = $this->crypto->getValueFromSignedString($signedString);

        $this->assertNull($result);
    }

    public function testConstructorThrowsExceptionForShortSecret(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Crypto('short');
    }

    /**
     * @dataProvider provideValidSignedStrings
     */
    public function testParseSignedStringValid(string $signedString, array $expectedData): void
    {
        $result = $this->crypto->parseSignedString($signedString);

        $this->assertIsArray($result);
        $this->assertEquals($expectedData, $result);
    }

    /**
     * @dataProvider provideInvalidSignedStrings
     */
    public function testParseSignedStringInvalid(string $signedString): void
    {
        $result = $this->crypto->parseSignedString($signedString);

        $this->assertNull($result);
    }

    /**
     * @dataProvider provideInsufficientDataStrings
     */
    public function testParseSignedStringInsufficientData(string $signedString): void
    {
        $result = $this->crypto->parseSignedString($signedString);

        $this->assertNull($result);
    }

    /**
     * @dataProvider provideUnpackFailureStrings
     */
    public function testParseSignedStringUnpackFailure(string $signedString): void
    {
        $result = $this->crypto->parseSignedString($signedString);

        $this->assertNull($result);
    }

    /**
     * @dataProvider provideParseDataUnpackFailure
     */
    public function testParseDataUnpackFailure(string $data): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected at least 1 byte, 0 given.');

        $this->crypto->parseData($data);
    }

    /**
     * @dataProvider provideParseDataMissingKeys
     */
    public function testParseDataMissingKeys(string $data): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected exactly 22 bytes, 21 given.');

        $this->crypto->parseData($data);
    }

    public static function provideValidSignedStrings(): array
    {
        // Construct a valid data string for version 1
        $version = \pack('C', 1);
        $sessionId = \hex2bin('abcdefabcdefabcdefabcdefabcdefabcdefabcd'); // 20 bytes
        $timestep = \pack('C', 10);
        $value = $version . $sessionId . $timestep;

        $signature = \hash_hmac('sha256', $value, self::SIGNATURE_SECRET);
        $encodedValue = Base64::encode($value);
        $signedString = $signature . '-' . $encodedValue;

        $expectedData = [
            'version' => 1,
            'sessionId' => 'abcdefabcdefabcdefabcdefabcdefabcdefabcd',
            'timestep' => 10,
        ];

        return [
            [$signedString, $expectedData],
        ];
    }

    public static function provideInvalidSignedStrings(): array
    {
        $invalidSignature = 'invalidsignature1234567890abcdef1234567890abcdef1234567890abcdef';
        $value = 'some_value';
        $encodedValue = Base64::encode($value);
        $signedString = $invalidSignature . '-' . $encodedValue;

        // Malformed signed string (missing '-')
        $malformedSignedString = 'invalidsignedstring';

        // Signed string with invalid Base64
        $signature = \hash_hmac('sha256', 'test_value', self::SIGNATURE_SECRET);
        $invalidBase64 = '!!!invalidbase64!!!';
        $signedStringInvalidBase64 = $signature . '-' . $invalidBase64;

        // Signed string with unknown version
        $unknownVersion = \pack('C', 2) . \str_repeat("\x00", 21); // Version 2 with arbitrary data
        $signatureUnknownVersion = \hash_hmac('sha256', $unknownVersion, self::SIGNATURE_SECRET);
        $encodedUnknownVersion = Base64::encode($unknownVersion);
        $signedStringUnknownVersion = $signatureUnknownVersion . '-' . $encodedUnknownVersion;

        return [
            [$signedString],
            [$malformedSignedString],
            [$signedStringInvalidBase64],
            [$signedStringUnknownVersion],
        ];
    }

    public static function provideInsufficientDataStrings(): array
    {
        // Data with version but insufficient length (missing timestep)
        $version = \pack('C', 1);
        $sessionId = \hex2bin('abcdefabcdefabcdefabcdefabcdefabcdefabcd'); // 20 bytes
        $value = $version . $sessionId; // Missing 1 byte for timestep

        $signature = \hash_hmac('sha256', $value, self::SIGNATURE_SECRET);
        $encodedValue = Base64::encode($value);
        $signedString = $signature . '-' . $encodedValue;

        return [
            [$signedString],
        ];
    }

    public static function provideUnpackFailureStrings(): array
    {
        // Data that fails to unpack (e.g., empty string after decoding)
        $value = ''; // Empty string
        $signature = \hash_hmac('sha256', $value, self::SIGNATURE_SECRET);
        $encodedValue = Base64::encode($value);
        $signedString = $signature . '-' . $encodedValue;

        // Data that is not properly packed (e.g., missing version byte)
        $valueMissingVersion = \hex2bin('abcdefabcdefabcdefabcdefabcdefabcdefabcd') . \pack('C', 10);
        $signatureMissingVersion = \hash_hmac('sha256', $valueMissingVersion, self::SIGNATURE_SECRET);
        $encodedMissingVersion = Base64::encode($valueMissingVersion);
        $signedStringMissingVersion = $signatureMissingVersion . '-' . $encodedMissingVersion;

        return [
            [$signedString],
            [$signedStringMissingVersion],
        ];
    }

    public static function provideParseDataUnpackFailure(): array
    {
        // Empty data string to cause parseData to throw 'Expected at least 1 byte, 0 given.'
        $data = '';

        return [
            [$data],
        ];
    }

    public static function provideParseDataMissingKeys(): array
    {
        // Data for version 1 but missing 'timestep' (length 21 instead of 22)
        $version = \pack('C', 1);
        $sessionId = \hex2bin('abcdefabcdefabcdefabcdefabcdefabcdefabcd'); // 20 bytes
        $data = $version . $sessionId; // Missing 1 byte for timestep

        return [
            [$data],
        ];
    }
}
