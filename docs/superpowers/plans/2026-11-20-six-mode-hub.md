# Six-mode hub implementation plan

> Use subagent-driven development for independent slices; the parent owns assembly and end-to-end verification.

**Goal:** Serve four BitTorrent modes and native AWG/WG simultaneously with transport-independent IPv4 addresses, group ACLs, and hub-only egress.

**Spec:** `local://six-mode-hub-design.md`.

**Global constraints:** Preserve current carrier optimizations; no automatic plain fallback or client default route; preserve existing enrollment and permissions on migration; unknown peers and prohibited flows fail closed. Use the isolated feature checkout containing the current performance changes.

## Slices and integration contracts

1. **Store:** add `GroupRecord{ID, Name, Subnet, ServerIP string; NoInternet bool; VisibleGroups []string}` and `ClientRecord{GroupID string; Internet *bool}` in addition to existing fields. A nil `VisiblePeers` on a group-managed user inherits; explicit list overrides; legacy normalized permissions must be preserved. Constant `DefaultGroupID`. Add `ListGroups`, `GetGroup`, `SaveGroup`, `DeleteGroup`, `AllocateClient(rec)`, `MoveClient(id, groupID)`. Validate and allocate inside bbolt transactions; preserve old CreateClient behavior used by existing callers/tests. Verify migration and short CIDRs, overlaps, exhausted pools, group moves.
2. **Carrier:** add `carrier.Accept(c, serverID [20]byte, hashes map[[20]byte]string) (carrier.Transport, [20]byte, error)` for `ext`/`req` dispatch off one incoming 68-byte handshake; wire format and request negotiation unchanged. Existing `NewExtended`/`NewRequestPiece` remain client API. Verify same listener accepts both without reading handshake twice.
3. **Client/config:** `config.ClientConfig` gains `CarrierHashes map[string]string`, `AWGEndpoint`, `WGEndpoint string`. Keep `Transport` as user selection, `InfoHash` legacy. Add `config.CarrierHash(base, preferred, mode string) (string,error)` for deterministic per-framing hashes; keep legacy base for old framing. Add explicit CLI selection, native devices, native config export renderer, IPv4 route behavior unchanged. Verify import round trip, selectable native modes and conventional native configs.
4. **Hub dataplane:** combine AWG native UDP and caravan `conn.Bind`; each incoming carrier gets unique endpoint; standard WG on separate UDP with canonical profile. Shared packet router uses authenticated `/32` and per-user last accepted engine. One hub TUN/netstack, group gateway addresses, common filtering and live policy; Linux scoped NAT and cleanup. Both TCP/UDP carrier listeners dispatch incoming framing, DHT announces both hashes. Tests cover stale disconnect, six peers, blocked source and native interop.
5. **Panel and docs:** groups, user create/move/revoke, inheritance and overrides, import and native export. Use active server config for imports and distinguish restart/re-import. Verify authenticated page, all transport configs, policy reload, real Linux forwarding and both CLI entry points. No deployment or push without explicit request.

   **Panel contract (implemented in `btawg/internal/panel`):**
   - `Registry` interface adds `Config() config.ServerConfig`; panel uses the active config for all client imports/exports.
   - Routes:
     - `GET /groups`, `GET /groups/edit`, `POST /groups/save`, `POST /groups/delete` — group CRUD.
     - `POST /clients/create` (with `group_id`), `POST /clients/move` — group assignment and reallocation.
     - `POST /clients/policy` — `internet` (`inherit`/`on`/`off`) and `peers` (`inherit`/`*`/list/`[]`); failed `ReloadPolicy` reverts the saved client record.
     - `GET /clients/import` — btawg:// string with `CarrierHashes` for all carrier modes, `AWGEndpoint`/`WGEndpoint` when `ExternalIP` is set, and managed `Routes`; revoked clients are refused.
     - `GET /clients/native?id=&mode=` — standard WG/AWG IPC config; requires `ExternalIP` and refuses revoked clients.
   - `GroupRecord.VisibleGroups`: `nil` = same group only, `[]` = none, `["*"]` = all, explicit list = those groups.
   - `ClientRecord.Internet` / `VisiblePeers`: `nil` = inherit from group; explicit value/list overrides.
   - Server settings form exposes all six modes plus `awg_port`/`wg_port`; pending vs active config is shown on the page.

## Pre-flight

| Producer → consumer | Shared contract | Decision |
|---|---|---|
| Store → hub and panel | Group membership, allocation, IPv4 policy inheritance | Legacy users keep explicit existing ACL. New group users inherit when their ACL is nil. |
| Carrier → hub | Single accept dispatch and public framing hash | Existing client-side handshakes retained. Hub owns endpoint and peer authentication. |
| Config → hub and panel | Carrier hashes, endpoint strings, native config | Same keys and assigned IP across modes. Per-framing hash, TCP/UDP use same port number. |
| Hub → panel | Application of policy, addresses, and peer registrations | Panel applies changes through hub; it must not claim success when runtime rejects them. |

## Review focus

- Mixed-mode traffic routes by authenticated peer, never by an untrusted BitTorrent ID alone.
- A client with denied egress cannot route directly or reuse an existing SOCKS5 association after a policy flip.
- Unknown source, overlap, IPv6, spoofed source and revoked peers do not forward.
- Failed group migration, runtime updates or partial startup do not silently leave wider access or zombie sockets.
- Peer-mode changes and DHT announce work without changing address; legacy imported endpoint uses its old hash.
