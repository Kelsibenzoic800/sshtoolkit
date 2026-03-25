# SSH Toolkit

Toolkit SSH completo no navegador: gere chaves, endureça servidores, configure
clientes e monte túneis. 100% client-side, zero tracking.

**https://sshtoolkit.otaviomiranda.com.br**

---

## Ferramentas

| Ferramenta | Rota | Descricao |
|------------|------|-----------|
| **Tunnel Builder** | [`/tunnels`](https://sshtoolkit.otaviomiranda.com.br/tunnels/) | Comandos de tunel SSH com diagramas visuais |
| **Server Hardening** | [`/hardening`](https://sshtoolkit.otaviomiranda.com.br/hardening/) | sshd_config endurecido com score de seguranca |
| **Client Config** | [`/config`](https://sshtoolkit.otaviomiranda.com.br/config/) | ~/.ssh/config com ProxyJump, drag-reorder e import |
| **Key Generator** | [`/keygen`](https://sshtoolkit.otaviomiranda.com.br/keygen/) | Chaves Ed25519/RSA via Web Crypto API |

### Tunnel Builder

Monte comandos de SSH Tunnel com diagramas visuais.

- Local Forward (`-L`), Remote Forward (`-R`), Dynamic/SOCKS (`-D`)
- Multiplos tuneis em um unico comando
- Flags: `-N`, `-f`, `-C`, `ExitOnForwardFailure`, keepalive
- Saida: comando SSH, `autossh` persistente, bloco `~/.ssh/config`
- Diagrama visual por tunel
- Cards de caso de uso: "Acessar banco remoto", "Expor servidor local", "Navegar via proxy"

### Server Hardening

Gere um `sshd_config` endurecido com score de seguranca.

- Presets: Paranoico (A+), Equilibrado (A), Permissivo (B)
- Score de seguranca 0-100 com nota A-F
- Warnings por severidade (danger, warn, info)
- Script de aplicacao (backup + test + restart)
- Tooltips explicando cada diretiva

### Client Config

Monte seu `~/.ssh/config` visualmente.

- CRUD de hosts com cards colapsaveis
- ProxyJump chain visualization (Voce → bastion → destino)
- Drag-and-drop para reordenar (a ordem importa no SSH)
- Import: cole um config existente e edite visualmente
- Opcoes avancadas: ForwardAgent, LocalForward, RemoteForward, etc.

### Key Generator

Gere pares de chaves Ed25519 e RSA direto no navegador via Web Crypto API.

- Ed25519 (recomendado), RSA 2048, RSA 4096
- Download individual ou ZIP com README de instrucoes
- Fingerprint SHA256
- Comando `ssh-copy-id` e permissoes (`chmod`) prontos para copiar
- Tooltips explicando cada tipo de chave

---

## Privacidade

Tudo roda no seu navegador. Nenhum dado sai da sua maquina. Sem API, sem
cookies, sem analytics. Abra o DevTools e confira a aba Network.

---

## Stack

- [Astro](https://astro.build/) 6.x — static site generator
- TypeScript 5.x
- Web Crypto API (keygen)
- [fflate](https://github.com/101arrowz/fflate) (ZIP)
- [Vitest](https://vitest.dev/) (testes)
- GitHub Pages (deploy)

---

## Desenvolvimento

```bash
# Requisitos: Node.js >= 22.12.0

# Instalar dependencias
npm install

# Dev server
npm run dev

# Rodar testes
npm test

# Build
npm run build
```

---

## Autor

**Otavio Miranda** — [otaviomiranda.com.br](https://www.otaviomiranda.com.br)

- [YouTube](https://www.youtube.com/@otaboranern)
- [GitHub](https://github.com/luizomf)

---

## Licenca

[MIT](./LICENSE)
