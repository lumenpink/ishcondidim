# Changelog

## [Unreleased]

### Features
  - initial implementation of postfix autocrypt level 1 milter in rust

### Bug Fixes
  - (build) configurar profile.release com LTO e strip, e crt-static musl (closes #4)
  - (milter) ignore SMFIC_MACRO without reply, support SMFIR_CHGHEADER and update Content-Type
  - (milter) parse SMFIC_HEADER with null delimiters and insert EOH CRLF

## Previous Releases

