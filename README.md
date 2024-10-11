# wsc-crypto-php

PoC of cryptographic utility functions for WoltLab Suite Core, implemented in PHP.

## Overview

This project provides cryptographic helper functions, including:

- **Creating secure signatures** based on the Keyed-Hash Message Authentication Code (HMAC) algorithm.
- **Base64 encoding and decoding** without cache-timing leaks.
- **Parsing and verifying signed strings** to ensure data integrity and authenticity.

## Installation

Use Composer to install the package:

```bash
composer require softcreatr/wsc-crypto-php
```

## Usage

For detailed usage examples, please refer to the [examples](./examples/) directory.

### Examples

- [Creating and Verifying a Signed String](./examples/createAndVerifySignedString.php)
- [Handling a Session Cookie](./examples/handleSessionCookie.php)
- [Parsing a Signed String Directly](./examples/parseSignedString.php)

## Testing

The project includes a comprehensive test suite using PHPUnit.

### Running Tests

1. **Install Dependencies:**

   Ensure all dependencies are installed via Composer:

    ```bash
    composer install
    ```

2. **Run PHPUnit with Coverage:**

   Execute the following command to run your tests and generate an HTML coverage report:

    ```bash
    ./vendor/bin/phpunit --coverage-html coverage
    ```

3. **View Coverage Report:**

   Open `coverage/index.html` in your browser to view detailed coverage statistics.

## License

This project is licensed under the [ISC License](https://github.com/SoftCreatR/wsc-crypto-php/blob/main/LICENSE.md). See the [LICENSE](https://github.com/SoftCreatR/wsc-crypto-php/blob/main/LICENSE.md) file for details.

## Author

- **Sascha Greuel**
- **Email:** [hello@1-2.dev](mailto:hello@1-2.dev)
- **GitHub:** [SoftCreatR](https://github.com/SoftCreatR)

## Security Considerations

- **Protect the `signatureSecret`:** Ensure that the signature secret is stored securely and not exposed in version control or logs.
- **Validate Inputs:** Always validate and sanitize inputs when dealing with signed strings to prevent security vulnerabilities.

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements and bug fixes.

## Acknowledgments

- [ParagonIE](https://github.com/paragonie) for their constant-time encoding library.
- Inspired by WoltLab's WCF Crypto utilities.
