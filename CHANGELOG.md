# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Documentation

- Add comprehensive Vietnamese technical documentation series for JWT and JOSE - ([0310142](https://github.com/haiphamngoc-dev/jwt-debugger/commit/031014298218fc61ab63d798e9600884edd1595b))

## [0.1.0] - 2026-09-18

### Documentation

- *(license)* Add MIT license file - ([b0d0af8](https://github.com/haiphamngoc-dev/jwt-debugger/commit/b0d0af85e4fb0557b38797acbc1eb0ccc96616ef))
- Add comprehensive documentation in English and Vietnamese - ([e649487](https://github.com/haiphamngoc-dev/jwt-debugger/commit/e649487fdb8d725ec9d2f776a4b1e0ac7447d4ba))

### Features

- *(utils)* Implement base64url, time, and duration helpers - ([995509a](https://github.com/haiphamngoc-dev/jwt-debugger/commit/995509a3a1746c7641eb67ccb4c2bbbdf48b3363))
- *(domain)* Implement core domain models, claims, algorithms, and verification types - ([3d38185](https://github.com/haiphamngoc-dev/jwt-debugger/commit/3d38185b01a193eb1302316b2ebd92bf91dede32))
- *(crypto)* Implement signature verification for HMAC, RSA, ECDSA, and EdDSA - ([a496875](https://github.com/haiphamngoc-dev/jwt-debugger/commit/a4968754da8960a129a5dd8d346ce2932f3cea47))
- *(jwk)* Implement JWK/JWKS parser, converter, and key selector - ([eaa9c8a](https://github.com/haiphamngoc-dev/jwt-debugger/commit/eaa9c8a5cc2bb71a696dfa375c078a2dc3a87166))
- *(infrastructure)* Implement filesystem, stdin reader, and secure remote JWKS fetcher - ([2578d12](https://github.com/haiphamngoc-dev/jwt-debugger/commit/2578d129f592a41a724e205cc9583b94c5b3309c))
- *(application)* Implement application layer for decode, inspect, validate, and verify - ([ff118f9](https://github.com/haiphamngoc-dev/jwt-debugger/commit/ff118f980e15561b45dcaf89efce42ec07b31701))
- *(cli)* Implement command-line interface with clap, exit codes, formatting, and subcommands - ([4bf4bd6](https://github.com/haiphamngoc-dev/jwt-debugger/commit/4bf4bd635b96785af6dd246bd917cd2f0c1d080f))

### Maintenance

- Init project - ([be70516](https://github.com/haiphamngoc-dev/jwt-debugger/commit/be70516a04b40d7dd60bd132f5ecc06dd0b3149f))
- Add git-cliff configuration - ([017efe7](https://github.com/haiphamngoc-dev/jwt-debugger/commit/017efe7e21e5750124d37c6c1be6c7360d5d1df3))
- Add changelog update workflow - ([54288aa](https://github.com/haiphamngoc-dev/jwt-debugger/commit/54288aacbdb067cf7ef166c7c9f152de1119e698))
- Add package metadata and initialize README - ([e523e7f](https://github.com/haiphamngoc-dev/jwt-debugger/commit/e523e7f3360dfe706feafb8c124dada84cba130d))
- Configure cargo-deny security policy and clippy linter settings - ([f03556f](https://github.com/haiphamngoc-dev/jwt-debugger/commit/f03556f2de0ffd6592422f40e5a08c1eac283b8c))
- Add release-linux workflow for automated multi-arch Linux binary packaging - ([68b1665](https://github.com/haiphamngoc-dev/jwt-debugger/commit/68b1665ce53ab70b6dbe7a92068b7778d52de517))

### Performance

- *(cargo)* Configure release profile optimizations with LTO, strip, and abort panic - ([1db114e](https://github.com/haiphamngoc-dev/jwt-debugger/commit/1db114ee8fabcf7856e463aacd4eb538bf558fba))

### Testing

- Add comprehensive integration test suites for all CLI commands and workflows - ([acfd10a](https://github.com/haiphamngoc-dev/jwt-debugger/commit/acfd10a27d8d774a133a49ad69d8f8dbc0facf13))
