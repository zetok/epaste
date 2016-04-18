# Epaste

**Epaste** encrypts given text and turns encrypted bytes it into `base64` text
which can be easily pasted/retrieved on pastebin website.

User needs to supply a password that will be used to encrypt / decrypt the
text.

Decrypting the text can fail only if provided data (`base64`) is not valid.

There is no hardcoded limit on size of data that is to be encrypted/decrypted.

## Usage

To encrypt data:

```bash
./epaste 'password' < 'file with text'
```

To decrypt data:

```bash
./epaste -d 'password' < 'file with encrypted text'
```

To decrypt data as raw bytes into a file:

```bash
./epaste -dr 'password' < 'file with encrypted data' > <output file>
```

## Packages / builds

### Generic

* [Linux x86_64](https://github.com/zetok/epaste/releases)

### Packages

* [Arch Linux](https://aur.archlinux.org/packages/epaste/)


## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | >=1.0.0 |

## Building
Fairly simple. You'll need [Rust] and [libsodium].

When you'll have deps, build debug version with
```bash
cargo build
```

## Goals
- [x] encrypt/decrypt message with given password
- [x] CLI interface
- [ ] GUI interface

## Support

If you like Epaste, feel free to help it by contributing, whether that would be
by writing code, suggesting improvements, or by donating.

Donate via Bitcoin: `1FSDbXVbUZSe34UqxJjfNMdAA9P8c6tNFQ`

*If you're interested in some other way of donating, please say so. :smile:*

## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[libsodium]: https://github.com/jedisct1/libsodium
[Rust]: https://www.rust-lang.org/
