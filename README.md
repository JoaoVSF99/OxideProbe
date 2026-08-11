# OxideProbe

[![CI](https://github.com/JoaoVSF99/OxideProbe/actions/workflows/ci.yml/badge.svg)](https://github.com/JoaoVSF99/OxideProbe/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Scanner assíncrono de portas TCP e identificador experimental de serviços, escrito em Rust com concorrência limitada e tratamento seguro de erros.

> English summary: OxideProbe is a bounded asynchronous TCP connect scanner and an experimental, data-driven service-identification engine. It is not a replacement for Nmap.

## Principais recursos

- conexões TCP assíncronas com timeout e concorrência limitada;
- alvo e portas configuráveis pela CLI;
- saída legível ou JSON;
- parser, scanner e tipos compartilhados separados em crates;
- testes com serviços simulados em `localhost`;
- CI com formatação, análise estática e testes automatizados.

O OxideProbe faz **TCP connect scan** usando a API de sockets do sistema operacional. Ele não cria pacotes SYN brutos, não tenta explorar vulnerabilidades e não implementa evasão.

## Arquitetura

| Componente | Responsabilidade |
|---|---|
| `oxideprobe-core` | Tipos compartilhados, portas e correspondência de assinaturas |
| `oxideprobe-parser` | Converte `nmap-service-probes` para JSON |
| `oxideprobe` | Verifica portas TCP e tenta identificar serviços |

## Requisitos

- Rust estável (edição 2021)
- Acesso à rede apenas se o parser for baixar a base de probes

## Uso rápido

Na raiz do workspace:

```bash
cargo run -p oxideprobe-parser -- --output probes.json
cargo run -p oxideprobe -- \
  --target 127.0.0.1 \
  --ports 22,80,443,8000-8010 \
  --probes probes.json
```

Para verificar somente quais portas aceitam uma conexão TCP, sem enviar probes de identificação:

```bash
cargo run -p oxideprobe -- \
  --target 127.0.0.1 \
  --ports 1-1024 \
  --no-service-detection
```

Saída JSON:

```bash
cargo run -p oxideprobe -- \
  --target 127.0.0.1 \
  --ports 22,80,443 \
  --no-service-detection \
  --json
```

Consulte todas as opções com:

```bash
cargo run -p oxideprobe -- --help
cargo run -p oxideprobe-parser -- --help
```

## Desenvolvimento

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Os testes de rede abrem listeners efêmeros exclusivamente em `127.0.0.1`; não dependem de alvos externos.

## Limitações conhecidas

- aceita um único endereço IPv4 ou IPv6 por execução;
- verifica apenas TCP; não há suporte a UDP ou SYN scan;
- a identificação de serviço implementa somente um subconjunto das expressões da base do Nmap;
- assinaturas PCRE incompatíveis com a crate `regex` são ignoradas sem interromper a execução;
- `fallback` é preservado pelo parser, mas ainda não é percorrido pelo scanner;
- o resultado “open” significa que uma conexão TCP foi aceita dentro do timeout, não que o serviço esteja seguro.

## Uso responsável

Execute apenas contra sistemas próprios ou com autorização explícita. Mesmo uma varredura simples pode violar políticas internas, contratos ou leis quando realizada sem permissão.

## Origem dos dados

O parser usa, por padrão, o arquivo [`nmap-service-probes`](https://github.com/nmap/nmap/blob/master/nmap-service-probes) mantido pelo Nmap Project. O arquivo gerado (`probes.json`) não é versionado neste repositório.

## Licença

Código disponibilizado sob a [licença MIT](LICENSE). Os dados e conteúdos provenientes do Nmap permanecem sujeitos aos termos do projeto de origem.
