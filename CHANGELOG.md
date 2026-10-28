# Changelog

## [Unreleased]

### Features
  - (updater) conformidade com padrao xdg e integracao com a banca (closes #3)
  - (ci) publicar release linux-x86_64 com tag latest na gambi (closes #5)
  - initial implementation of postfix autocrypt level 1 milter in rust

### Bug Fixes
  - (ci) podar asset previo de release para evitar erro 404 (closes #7)
  - (build) configurar profile.release com LTO e strip, e crt-static musl (closes #4)
  - (milter) ignore SMFIC_MACRO without reply, support SMFIR_CHGHEADER and update Content-Type
  - (milter) parse SMFIC_HEADER with null delimiters and insert EOH CRLF

## Previous Releases

