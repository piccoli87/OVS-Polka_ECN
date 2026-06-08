# Relatório de Análise e Correção de Bugs — OVS ECN/POLKA
**Data:** 2026-06-05
**Projeto:** Open vSwitch estendido com ECN/AccECN, AQM CoDel e PolKA source routing
**Diretório:** `OVS_ECN_POLKA-v1/ovs/`

---

## 1. Contexto

Fork do Open vSwitch com três extensões independentes:

| Extensão | Arquivos principais |
|---|---|
| ECN / AccECN (RFC 3168, RFC 9331) | `lib/packets.h`, `lib/packets.c`, `lib/conntrack-tcp.c`, `lib/ct-dpif.h/c` |
| AQM CoDel (RFC 8289) | `lib/aqm.h`, `lib/aqm.c`, `lib/dpif-netdev.c` |
| PolKA source routing | `lib/polka.h`, `lib/polka.c`, `lib/flow.c`, `ofproto/ofproto-dpif-xlate.c`, `vswitchd/bridge.c` |

### Algoritmo PolKA implementado

Cada pacote PolKA carrega um campo `routeId` de **160 bits (20 bytes)** no cabeçalho Ethernet (etherType `0x1234`). O `routeId` é inserido uma única vez pelo nó de origem e **não é alterado** em nenhum nó intermediário — permanece idêntico do início ao fim da rota.

Cada switch computa a porta de saída localmente:

```
ndata  = routeId[0..17]   (bytes 0–17, 144 bits = campo de entrada do CRC)
dif    = routeId[18..19]  (bytes 18–19, 16 bits, big-endian)
porta  = CRC16(ndata, nodeId) XOR dif
```

O `nodeId` é o polinômio CRC-16 único do switch (configurado via
`ovs-vsctl set Bridge <name> other_config:polka-node-id=<hex>`).

### Sintoma relatado

> *"Ao realizar testes de conectividade usando o protocolo POLKA via ping, apenas o primeiro pacote é recebido."*

---

## 2. Análise dos Arquivos

### Fluxo de um pacote PolKA no OVS

```
pacote entra na porta
    └─ miniflow_extract()          [lib/flow.c]
           dl_type == 0x1234 →
           routeId armazenado em flow->regs[0..4]
           goto out  (sem parsear L4)
    └─ DPCLS lookup
           miss → upcall (slow path)
    └─ xlate_normal()              [ofproto/ofproto-dpif-xlate.c]
           dl_type == ETH_TYPE_POLKA && polka_node_poly != 0 →
           xlate_polka()
    └─ xlate_polka()
           reconstrói routeId de regs[0..4]
           polka_compute_nhop() → porta
           compose_output_action()
           megaflow instalado no DPCLS
```

---

## 3. Bugs Identificados

### Bug 1 — CRÍTICO (causa direta do sintoma)
**Arquivo:** `ovs/ofproto/ofproto-dpif-xlate.c`
**Função:** `xlate_polka()`

#### Descrição

As máscaras de wildcard `wc->masks.regs[0..4]` eram definidas como `UINT32_MAX`
(match exato no routeId) **somente após** a verificação de existência do porto
calculado. Se `get_ofp_port()` retornava `NULL` (porto não encontrado), a função
retornava imediatamente **sem setar as máscaras**.

#### Código com bug

```c
struct xport *xport = get_ofp_port(xbr, ofp_port);
if (!xport) {
    xlate_report(ctx, OFT_WARN, "PolKA: computed port %u not found ...");
    return;                            // ← retorna SEM definir as máscaras!
}

/* Só chegava aqui se xport != NULL: */
wc->masks.regs[0] = UINT32_MAX;
wc->masks.regs[1] = UINT32_MAX;
wc->masks.regs[2] = UINT32_MAX;
wc->masks.regs[3] = UINT32_MAX;
wc->masks.regs[4] = UINT32_MAX;

compose_output_action(ctx, ofp_port, NULL, true, false);
```

#### Por que isso causava "apenas o primeiro pacote recebido"

No caso de porto não encontrado, o megaflow instalado possuía:
- **Chave de match:** apenas `dl_type=0x1234` + `in_port=X` (sem match no routeId)
- **Ação:** vazia (drop implícito)

Esse megaflow **amplo** capturava **todos** os pacotes PolKA subsequentes chegando
naquela porta de entrada, independentemente do routeId, e os descartava silenciosamente.

O primeiro pacote era processado pelo slow-path antes do megaflow ser instalado.
A partir do segundo pacote, o megaflow amplo assumia o controle e todos eram descartados.

#### Código corrigido

```c
/* Máscaras definidas ANTES da verificação do porto: mesmo no caso de
 * drop, o megaflow faz match apenas neste routeId específico e não
 * captura pacotes de outros caminhos. */
wc->masks.regs[0] = UINT32_MAX;
wc->masks.regs[1] = UINT32_MAX;
wc->masks.regs[2] = UINT32_MAX;
wc->masks.regs[3] = UINT32_MAX;
wc->masks.regs[4] = UINT32_MAX;

struct xport *xport = get_ofp_port(xbr, ofp_port);
if (!xport) {
    xlate_report(ctx, OFT_WARN, "PolKA: computed port %u not found ...");
    return;
}

compose_output_action(ctx, ofp_port, NULL, true, false);
```

---

### Bug 3 — AQM CoDel trata pacotes PolKA como pacotes IP
**Arquivo:** `ovs/lib/aqm.c`
**Função:** `aqm_codel_run()`

#### Descrição

No path de TX do datapath PMD (`dpif-netdev.c`), o AQM CoDel é aplicado a
**todos** os pacotes do batch de saída, inclusive pacotes PolKA.

Para qualquer pacote, `miniflow_extract()` define `packet->l3_ofs` apontando
para o byte imediatamente após o cabeçalho Ethernet. Para pacotes PolKA, isso
significa que `dp_packet_l3(pkt)` retorna um ponteiro para `route_id[0]` —
**não** para um cabeçalho IP.

As funções de ECN chamadas pelo CoDel (`pkt_is_ipv6`, `IP_ECN_set_ce_safe`)
assumiam que `dp_packet_l3()` aponta para um cabeçalho IP e operavam
diretamente sobre os bytes do routeId:

```c
// pkt_is_ipv6 — verifica nibble de versão IP:
const uint8_t *l3 = dp_packet_l3(pkt);       // ← aponta para routeId[0]!
return l3 && ((*l3 >> 4) == 6);              // nibble superior de routeId[0]

// IP_ECN_set_ce_safe — acessa campo ip_tos do cabeçalho IP:
struct ip_header *nh = dp_packet_l3(pkt);    // ← routeId!
uint8_t tos = nh->ip_tos;                    // ← routeId[1] como se fosse TOS!
```

#### Consequências

| Situação | Efeito |
|---|---|
| `routeId[1] & 0x03 != 0` (bits ECN não-zero) | CE bits setados em `routeId[1]` → **routeId corrompido** → switch seguinte calcula porto errado |
| `routeId[1] & 0x03 == 0` (Not-ECT) | `aqm_codel_run` retorna 0 → **`packets[0]` descartado** pelo caller |

Só ocorre com batch ≥ 2 pacotes **e** CoDel em estado de dropping
(sojourn > 5 ms por mais de 100 ms). Em pings simples (1 pkt/s), improvável.
Em flood pings ou alta carga, manifesta-se como descarte ou roteamento incorreto.

#### Código corrigido

Adicionada função auxiliar `pkt_is_polka()` e guarda de proteção no loop
de CE-marking:

```c
/* Nova função auxiliar: */
static bool
pkt_is_polka(const struct dp_packet *pkt)
{
    if (!dp_packet_is_eth(pkt)) {
        return false;
    }
    const struct eth_header *eth = dp_packet_data(pkt);
    return eth->eth_type == htons(ETH_TYPE_POLKA);
}

/* Loop de CE-marking modificado: */
DP_PACKET_BATCH_FOR_EACH (i, pkt, batch) {
    if (pkt_is_polka(pkt)) {
        continue;   /* routeId ≠ cabeçalho IP — não aplicar ECN */
    }
    bool is_v6 = pkt_is_ipv6(pkt);
    if (IP_ECN_set_ce_safe(pkt, is_v6)) {
        COVERAGE_INC(aqm_ce_marked);
        goto marked;
    }
}
```

---

## 4. Bug 4 — CAUSA RAIZ DO SINTOMA (identificado na segunda análise)
**Arquivo:** `ovs/vswitchd/bridge.c` — função que lê `polka-node-id` do OVSDB (~linha 4119)

### Descrição

Este é o **bug principal** que causa o sintoma "apenas o primeiro pacote recebido".

#### A cadeia de propagação do polinômio

```
OVSDB (other_config:polka-node-id)
    ↓  bridge_reconfigure()          [bridge.c]
dpif_ofproto->polka_node_poly        [ofproto_dpif struct]
    ↓  xlate_ofproto_set()           [ofproto-dpif.c, só chamado quando need_revalidate != 0]
xbridge->polka_node_poly             [xlate layer]
    ↓  xlate_normal() verifica
xlate_polka() chamado (ou não)
```

#### O problema

`ofproto_set_fail_mode()` (chamado ANTES da atribuição do polinômio em `bridge_reconfigure`)
delega apenas ao `connmgr` e **não seta `backer->need_revalidate`**. Isso significa
que `xlate_ofproto_set` **nunca é chamado** com o novo valor de `polka_node_poly`, e
`xbridge->polka_node_poly` permanece em **0 indefinidamente**.

Com `xbridge->polka_node_poly == 0`, a condição em `xlate_normal()` é falsa:

```c
if (flow->dl_type == htons(ETH_TYPE_POLKA)
    && ctx->xbridge->polka_node_poly != 0) {   // ← SEMPRE FALSO!
    xlate_polka(ctx);
    return;
}
```

Pacotes PolKA caem no caminho L2 normal → flooding (para dst broadcast).

#### Por que apenas o primeiro pacote chega

O **primeiro pacote** vai pelo slow-path (upcall). Sem polka_node_poly configurado,
cai no L2 flooding → chega ao destino ✓.

Em seguida, outro evento qualquer aciona uma revalidação. `xlate_ofproto_set` é chamado
agora com `polka_node_poly = 0x8005`. O fluxo L2 antigo é descartado. O **segundo pacote**
vai pelo slow-path novamente, agora com `xlate_polka` ativo.

Se `xlate_polka` calcular um porto inexistente (routeId mal calculado, numeração de
porto diferente, etc.), instala um megaflow de drop — e todos os pacotes seguintes
são descartados.

#### Código com bug

```c
if (dpif_ofproto) {
    dpif_ofproto->polka_node_poly = (uint16_t)poly_val;
    // ← Não dispara need_revalidate!
    // ← xbridge->polka_node_poly permanece em 0
}
```

#### Código corrigido

```c
if (dpif_ofproto) {
    uint16_t new_poly = (uint16_t)poly_val;
    if (dpif_ofproto->polka_node_poly != new_poly) {
        dpif_ofproto->polka_node_poly = new_poly;
        /* Força revalidação para que xlate_ofproto_set() propague
         * o novo polinômio para a camada xlate imediatamente. */
        dpif_ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }
}
```

---

## 5. Bugs Descartados Durante a Análise

### "routeId não é atualizado no pacote" — NÃO é bug
Inicialmente considerado como possível bug (falta de shift `routeId >> 16` ao
estilo do P4 de referência). Confirmado pelo usuário que o protocolo PolKA
implementado aqui usa o **mesmo routeId sem alteração** em todos os nós,
ao contrário da versão P4 com shift. O comportamento do `xlate_polka` de
não modificar o payload é **correto e intencional**.

---

## 6. Arquivos Modificados

### `ovs/vswitchd/bridge.c` ← **CORREÇÃO PRINCIPAL** (Bug 4)
- **Função:** bloco de leitura de `polka-node-id` (~linha 4119)
- **Mudança:** Adicionada verificação de mudança de valor + disparo de
  `backer->need_revalidate = REV_RECONFIGURE` quando o polinômio muda.

### `ovs/ofproto/ofproto-dpif-xlate.c` (Bug 1)
- **Função:** `xlate_polka()` (aprox. linha 3215)
- **Mudança:** Movidas as 5 linhas `wc->masks.regs[i] = UINT32_MAX` para
  **antes** da chamada `get_ofp_port()`.

### `ovs/lib/aqm.c` (Bug 3)
- **Adição:** Função estática `pkt_is_polka()` (após `pkt_is_ipv6()`)
- **Mudança:** Loop `DP_PACKET_BATCH_FOR_EACH` em `aqm_codel_run()` —
  inserido `if (pkt_is_polka(pkt)) { continue; }` antes das chamadas ECN.

---

## 6. Arquivos Relevantes para Consulta Futura

| Arquivo | Responsabilidade |
|---|---|
| `lib/polka.h` / `lib/polka.c` | Algoritmo CRC-16 e cálculo de porto (`polka_compute_nhop`) |
| `lib/flow.c` | `miniflow_extract()` — parsing do routeId em `regs[0..4]` |
| `ofproto/ofproto-dpif-xlate.c` | `xlate_polka()`, `xlate_normal()` — encaminhamento no slow-path |
| `vswitchd/bridge.c` | Leitura de `polka-node-id` do OVSDB |
| `lib/aqm.h` / `lib/aqm.c` | CoDel AQM — marcação CE e descarte Not-ECT |
| `lib/dpif-netdev.c` | Loop PMD — integração do AQM no TX batch |
| `lib/packets.h` | `struct polka_header`, `ETH_TYPE_POLKA`, helpers ECN |
| `polka_switch.py` | Helper Mininet — classe `PolkaSwitch` |

---

## 7. Topologia de Referência para Testes (Mininet)

```
H1 (10.0.0.1) ─── s1 (nodeId=0x8005) ─── s2 (nodeId=0x1021) ─── s3 (nodeId=0x0589) ─── H2 (10.0.0.2)
```

Configuração equivalente via `polka_switch.py`:
```python
from polka_switch import PolkaSwitch
net = Mininet(controller=None, link=TCLink)
s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
s3 = net.addSwitch('s3', cls=PolkaSwitch, nodeId='0x0589')
h1 = net.addHost('h1', ip='10.0.0.1/24')
h2 = net.addHost('h2', ip='10.0.0.2/24')
net.addLink(h1, s1); net.addLink(s1, s2)
net.addLink(s2, s3); net.addLink(s3, h2)
```

Verificação após correção:
```bash
# Ver megaflow instalado (deve conter match em regs):
ovs-dpctl dump-flows | grep "dl_type=0x1234"

# Trace do pipeline:
ovs-appctl ofproto/trace s1 "in_port=1,dl_type=0x1234"

# Verificar se AQM está afetando pacotes PolKA:
ovs-appctl coverage/show | grep aqm_
```

---

## 8. Pendências / Próximos Passos

- [ ] Recompilar o OVS com as correções e executar a topologia T4 do README
- [ ] Validar que múltiplos pacotes PolKA são encaminhados corretamente
- [ ] Testar cenário com congestionamento (CoDel ativo) para confirmar Bug 3 corrigido
- [ ] Avaliar se o cálculo `polka_crc16(route_id, 18, node_poly)` é compatível
      com o P4 de referência para routeIds com bytes 16–17 não-nulos
      (ver discussão na sessão de análise)
