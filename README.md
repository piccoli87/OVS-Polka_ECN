# Open vSwitch Estendido — ECN, AccECN, AQM CoDel e PolKA

Este repositório contém um fork do **Open vSwitch** com três conjuntos de extensões independentes:

| Extensão | RFCs / Especificações | Descrição resumida |
|---|---|---|
| **ECN / AccECN** | RFC 3168, RFC 9331 | Suporte completo a Explicit Congestion Notification no plano de dados e conntrack |
| **AQM CoDel** | RFC 8289 | Active Queue Management automático por porta TX no PMD userspace |
| **PolKA** | polka-core.p4 | Source routing baseado em CRC-16; nenhum controlador necessário |

Todas as extensões operam **sem controlador OpenFlow** — o switch funciona de forma autônoma.

---

## Índice

1. [Visão Geral das Extensões](#1-visão-geral-das-extensões)
2. [Estrutura do Repositório](#2-estrutura-do-repositório)
3. [Pré-requisitos e Build](#3-pré-requisitos-e-build)
4. [Modos de Operação do Switch](#4-modos-de-operação-do-switch)
5. [ECN e AccECN — Configuração](#5-ecn-e-accecn--configuração)
6. [AQM CoDel — Configuração e Ajuste](#6-aqm-codel--configuração-e-ajuste)
7. [PolKA — Source Routing](#7-polka--source-routing)
8. [Topologias Mininet](#8-topologias-mininet)
9. [Matriz de Cenários](#9-matriz-de-cenários)
10. [Exemplos Completos](#10-exemplos-completos)
11. [Verificação e Diagnóstico](#11-verificação-e-diagnóstico)
12. [Referência Rápida de Comandos](#12-referência-rápida-de-comandos)

---

## 1. Visão Geral das Extensões

### 1.1 ECN / AccECN

| Componente | Arquivo | Função |
|---|---|---|
| `IP_ECN_is_capable()` | `lib/packets.h` | Retorna true para ECT(0) ou ECT(1) |
| `IP_ECN_is_ect1()` | `lib/packets.h` | Identifica tráfego L4S — ECT(1), RFC 9331 |
| `IP_ECN_set_ce_safe()` | `lib/packets.c` | Marca CE somente em pacotes ECN-capazes; ignora Not-ECT |
| `TCP_AE` | `lib/packets.h` | Alias do bit TCP NS para negociação AccECN |
| ECN tracking | `lib/conntrack-tcp.c` | Rastreia handshake ECN/AccECN por conexão TCP |
| `CT_DPIF_ECN_*` | `lib/ct-dpif.h` | Expõe estado ECN na API pública de conntrack |

**Codepoints ECN no campo DS do IP (2 bits):**

| Valor | Codepoint | Significado |
|---|---|---|
| `0x00` | Not-ECT | Sem ECN; AQM descarta sob congestionamento |
| `0x01` | ECT(1) | ECN-capable; identifica tráfego L4S (RFC 9331) |
| `0x02` | ECT(0) | ECN-capable; ECN clássico (RFC 3168) |
| `0x03` | CE | Congestion Experienced — marcado pelo AQM |

**Negociação TCP (handshake):**
- SYN com `ECE + CWR` → iniciador solicita ECN → conntrack registra `CT_ECN_INIT`
- SYN-ACK com `ECE` (sem CWR) → ECN confirmado → `CT_ECN_CONFIRMED`
- SYN com `ECE + CWR + AE(NS)` → AccECN solicitado → `CT_ECN_ACCECN`

### 1.2 AQM CoDel

Implementa o algoritmo **CoDel (RFC 8289)** adaptado ao modelo de TX-batch do PMD do OVS. O AQM é por porta de saída e opera sem nenhuma configuração adicional.

**Parâmetros padrão:**

| Parâmetro | Valor padrão | Significado |
|---|---|---|
| `AQM_CODEL_TARGET_US` | 5 000 µs (5 ms) | Sojourn alvo — fila saudável abaixo deste valor |
| `AQM_CODEL_INTERVAL_US` | 100 000 µs (100 ms) | Janela de marcação — após este tempo acima do alvo, inicia marcação |

**Comportamento:**
- Pacote **ECT(0) ou ECT(1)**: recebe marcação **CE** (sem descarte)
- Pacote **Not-ECT**: descartado quando o AQM dispararia CE

### 1.3 PolKA (Polynomial Key-based Architecture)

Source routing em que o caminho completo é codificado num campo de **160 bits (`routeId`)** carregado no próprio pacote (etherType `0x1234`). Cada switch computa a porta de saída localmente via CRC-16, sem tabela de roteamento distribuída e sem controlador.

**Algoritmo por switch:**

```
ndata  = routeId[0..17]          (18 bytes = 144 bits superiores)
dif    = routeId[18..19]         (2  bytes = 16  bits inferiores, big-endian)
porta  = CRC16(ndata, nodeId) XOR dif
```

O `nodeId` é o polinômio CRC-16 único do switch — seu "endereço" na topologia PolKA.

---

## 2. Estrutura do Repositório

```
Proj_OpenVSwitch/
├── ovs/                        ← código-fonte OVS modificado
│   ├── lib/
│   │   ├── aqm.h / aqm.c       ← AQM CoDel (novo)
│   │   ├── polka.h / polka.c   ← PolKA CRC-16 (novo)
│   │   ├── packets.h / .c      ← ECN helpers + struct polka_header
│   │   ├── flow.c              ← parsing PolKA routeId em miniflow
│   │   ├── conntrack-tcp.c     ← rastreamento ECN/AccECN no handshake
│   │   ├── ct-dpif.h / .c      ← estado ECN na API de conntrack
│   │   ├── dpif-netdev.c       ← integração AQM no loop PMD
│   │   └── automake.mk         ← registro dos novos arquivos
│   ├── ofproto/
│   │   ├── ofproto-dpif.h      ← campo polka_node_poly
│   │   ├── ofproto-dpif.c      ← repasse de polka_node_poly ao xlate
│   │   ├── ofproto-dpif-xlate.h← assinatura xlate_ofproto_set atualizada
│   │   └── ofproto-dpif-xlate.c← xlate_polka() + hook em xlate_normal()
│   └── vswitchd/
│       └── bridge.c            ← leitura polka-node-id + failMode=polka
├── polka_switch.py             ← helper Mininet (classe PolkaSwitch)
├── polka-core.p4               ← referência P4 do algoritmo PolKA
└── README.md                   ← este arquivo
```

---

## 3. Pré-requisitos e Build

### Dependências

```bash
sudo apt-get install -y \
  build-essential autoconf automake libtool \
  libssl-dev libcap-ng-dev python3-dev \
  python3-six python3-sphinx \
  linux-headers-$(uname -r)
```

### Compilar e instalar OVS

```bash
cd ovs/
./boot.sh
./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc
make -j$(nproc)
sudo make install
sudo make modules_install   # módulo de kernel (datapath)
sudo depmod -a
```

### Iniciar o OVS

```bash
sudo /usr/share/openvswitch/scripts/ovs-ctl start
ovs-vsctl --version   # verificar versão
```

### Instalar Mininet

```bash
git clone https://github.com/mininet/mininet
cd mininet
sudo util/install.sh -n   # só Mininet, sem OVS nativo
```

---

## 4. Modos de Operação do Switch

Este OVS suporta três modos de operação, todos **sem controlador**:

| Modo | `fail_mode` | Encaminhamento | Quando usar |
|---|---|---|---|
| **Standalone** | `standalone` | Aprendizado L2 automático (`NORMAL`) | Topologias simples, ECN/AQM |
| **Static flows** | `secure` | Regras OpenFlow inseridas manualmente | Controle fino de encaminhamento |
| **PolKA** | `polka` ou `standalone` + `nodeId` | CRC-16 sobre `routeId` do pacote | Source routing sem controlador |

> **Nota:** `fail_mode=polka` é reconhecido por `vswitchd/bridge.c` como alias de `standalone`. O encaminhamento PolKA é ativado quando `other_config:polka-node-id` é configurado com um valor não-zero.

### Standalone

```bash
ovs-vsctl add-br s1
ovs-vsctl set-fail-mode s1 standalone
# Nenhuma regra adicional necessária; aprendizado de MAC automático.
```

### Static flows

```bash
ovs-vsctl add-br s1
ovs-vsctl set-fail-mode s1 secure

# Encaminhamento genérico:
ovs-ofctl add-flow s1 "priority=100,action=normal"

# Ou regras direcionais por porta:
ovs-ofctl add-flow s1 "in_port=1,action=output:2"
ovs-ofctl add-flow s1 "in_port=2,action=output:1"
ovs-ofctl add-flow s1 "priority=0,action=drop"
```

### PolKA

```bash
ovs-vsctl add-br s1
# "polka" é um alias de standalone reconhecido pelo vswitchd:
ovs-vsctl set-fail-mode s1 polka
# Ou equivalentemente:
# ovs-vsctl set-fail-mode s1 standalone

# Definir o nodeId (polinômio CRC-16 único deste switch):
ovs-vsctl set Bridge s1 other_config:polka-node-id=0x8005
```

Quando `polka-node-id` muda, o bridge força uma revalidação interna (`REV_RECONFIGURE`) para que o novo polinômio seja propagado imediatamente à camada de tradução de fluxos (`xlate_ofproto_set`).

Em Mininet, usando o helper `polka_switch.py`:

```python
from polka_switch import PolkaSwitch

net = Mininet(controller=None)
s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
```

---

## 5. ECN e AccECN — Configuração

### 5.1 Configuração nos hosts (sysctl)

```bash
# ECN desabilitado (padrão em muitos sistemas)
sysctl -w net.ipv4.tcp_ecn=0

# ECN habilitado — inicia e aceita negociação
sysctl -w net.ipv4.tcp_ecn=1

# ECN passivo — aceita, mas não inicia
sysctl -w net.ipv4.tcp_ecn=2

# Não fazer fallback em redes que bloqueiam ECN
sysctl -w net.ipv4.tcp_ecn_fallback=0
```

Para persistir entre reboots:
```bash
echo "net.ipv4.tcp_ecn=1" >> /etc/sysctl.d/99-ecn.conf
sysctl --system
```

### 5.2 Flows OpenFlow com match ECN

```bash
# Prioridade alta para tráfego ECN-capaz:
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=1,action=normal"  # ECT(1)/L4S
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=2,action=normal"  # ECT(0)
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=3,action=normal"  # CE (já marcado)

# Tráfego Not-ECT — AQM descartará sob congestionamento:
ovs-ofctl add-flow s1 "priority=100,ip,nw_ecn=0,action=normal"

# Resto (ARP, IPv6, etc.):
ovs-ofctl add-flow s1 "priority=1,action=normal"
```

### 5.3 Forçar codepoint ECT(1) via tc (L4S)

```bash
# Marcar saída do host com ECT(1) — tráfego L4S (RFC 9331):
tc qdisc add dev eth0 root handle 1: prio
tc filter add dev eth0 parent 1: protocol ip u32 match ip tos 0x00 0xff \
   action pedit ex munge ip tos set 0x01   # ECT(1)
```

### 5.4 Consultar estado ECN no conntrack

```bash
ovs-dpctl dump-conntrack

# Saídas possíveis no campo ecn=:
#   ecn=init       → SYN com ECE+CWR visto (RFC 3168)
#   ecn=confirmed  → ECN confirmado no SYN-ACK
#   ecn=accecn     → AccECN negociado (bit AE no SYN)
```

---

## 6. AQM CoDel — Configuração e Ajuste

O AQM é **sempre ativo** no caminho TX do PMD. Não requer configuração para funcionar com os parâmetros padrão.

### 6.1 Verificar se o AQM está disparando

```bash
ovs-appctl coverage/show | grep -E "aqm_ce_marked|aqm_drop_not_ect|aqm_codel_enter"

# Exemplo de saída sob congestionamento:
# aqm_ce_marked       1234   — pacotes com CE marcado
# aqm_drop_not_ect      89   — pacotes Not-ECT descartados
# aqm_codel_enter        5   — entradas no dropping state
```

### 6.2 Ajustar parâmetros (requer recompilação)

Editar `lib/aqm.h` antes do build:

```c
#define AQM_CODEL_TARGET_US    5000LL    /* alvo de sojourn (µs) */
#define AQM_CODEL_INTERVAL_US  100000LL  /* janela de marcação (µs) */
```

| Cenário | `TARGET_US` | `INTERVAL_US` | Efeito |
|---|---|---|---|
| LAN de baixa latência | 1 000 (1 ms) | 20 000 (20 ms) | Mais agressivo |
| WAN / enlace com delay | 15 000 (15 ms) | 150 000 (150 ms) | Mais tolerante |
| Padrão RFC 8289 | 5 000 (5 ms) | 100 000 (100 ms) | Equilibrado |
| Carga intensa | 2 000 (2 ms) | 50 000 (50 ms) | Reação rápida |

### 6.3 Como o AQM decide marcar ou descartar

```
Pacote chega ao batch de saída (batch vazio)
  → batch_enqueue_us = now (timestamp do batch)

Na hora do flush (netdev_send), se batch ≥ 2 pacotes:
  sojourn = now - batch_enqueue_us

  sojourn ≤ 5 ms  →  fila saudável, envia normalmente
  sojourn > 5 ms por mais de 100 ms  →  congestionamento detectado:
    ├─ pacote ECT(0) ou ECT(1)?  → marca CE (IP_ECN_set_ce_safe), sem descarte
    └─ pacote Not-ECT?           → descarta packets[0] do batch (caller compacta o array)
```

> O AQM só atua quando o batch tem **≥ 2 pacotes** para evitar que a ação de descarte esvazie completamente o batch antes do envio — o que causaria divisão por zero na contabilidade de ciclos do PMD.

---

## 7. PolKA — Source Routing

### 7.1 Conceito

Cada pacote PolKA carrega um campo `routeId` de **160 bits** no cabeçalho (após Ethernet, etherType `0x1234`). O switch não mantém tabela de rotas: a porta de saída é calculada na chegada:

```
porta = CRC16(routeId[0..17], nodeId) XOR routeId_u16(bytes 18-19)
```

O `nodeId` é o polinômio CRC-16 exclusivo do switch. O configurador da rede escolhe os polinômios e os `routeId`s de modo que a equação produza a porta correta em cada nó ao longo do caminho.

**Encaminhamento stateless — sem megaflow cache:**

PolKA é inerentemente stateless: rotas distintas passam pelo mesmo switch com `routeId`s diferentes. Por isso, `ofproto-dpif-upcall.c` **proíbe** a instalação de megaflows para etherType `0x1234`. Todo pacote PolKA percorre o slow-path (upcall) para que `xlate_polka()` leia o `routeId` diretamente dos bytes brutos do pacote e compute o next-hop correto.

> **Por que não usar `flow->regs`?** No datapath de kernel, o ODP key do upcall nunca inclui `regs` para ethertypes desconhecidos — o kernel não decodifica o cabeçalho PolKA. Ler `regs` retornaria sempre zero, fazendo todos os pacotes serem encaminhados para a mesma porta (errada). A função `xlate_polka()` lê os bytes do pacote original (`ctx->xin->packet`) como fallback, e `lib/flow.c` usa a técnica de `nw_src = 0xFFFFFFFF` (sentinel) para garantir que o kernel nunca instale um megaflow que casaria com todos os pacotes PolKA da mesma porta de entrada.

### 7.2 Configuração do switch

```bash
# Via ovs-vsctl (direto):
ovs-vsctl set Bridge s1 other_config:polka-node-id=0x8005

# Verificar:
ovs-vsctl get Bridge s1 other_config
```

### 7.3 Configuração no Mininet com `polka_switch.py`

```python
#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from polka_switch import PolkaSwitch  # helper incluso no repositório

def run():
    net = Mininet(controller=None, link=TCLink)

    # Cada switch recebe um nodeId (polinômio CRC-16) único:
    s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
    s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
    s3 = net.addSwitch('s3', cls=PolkaSwitch, nodeId='0x0589')

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, h2)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
```

### 7.4 Enviar pacotes PolKA (Scapy)

```python
from scapy.all import Ether, IP, TCP, Raw, sendp

# routeId de 160 bits: 18 bytes ndata + 2 bytes dif
# O dif codifica a porta de saída em cada switch após o XOR com o CRC.
route_id = b'\x00' * 18 + b'\x03\x02'   # exemplo: porta 3 em s1, porta 2 em s2

pkt = (Ether(dst='ff:ff:ff:ff:ff:ff', type=0x1234) /
       Raw(load=route_id) /
       IP(dst='10.0.0.2') / TCP())

sendp(pkt, iface='h1-eth0')
```

### 7.5 Verificar encaminhamento PolKA

```bash
# Confirmar que o nodeId foi aplicado:
ovs-vsctl get Bridge s1 other_config

# Listar flows PolKA no datapath (apenas no datapath=netdev / userspace):
# NOTA: no datapath de kernel, megaflows para 0x1234 NÃO são instalados —
# cada pacote PolKA percorre o slow-path (upcall) intencionalmente.
ovs-dpctl dump-flows | grep "dl_type=0x1234"

# Trace do pipeline de encaminhamento:
ovs-appctl ofproto/trace s1 \
  "in_port=1,dl_type=0x1234,dl_dst=ff:ff:ff:ff:ff:ff"
```

### 7.6 Convivência PolKA + ECN

O PolKA encaminha pacotes com etherType `0x1234`. Pacotes IP normais continuam usando aprendizado L2. O AQM CoDel atua em **todas** as portas TX, incluindo PolKA — se um pacote PolKA transportar IP com ECT(0)/ECT(1) no payload, o AQM marcará CE no campo ECN normalmente.

---

## 8. Topologias Mininet

### T1 — Single switch (referência)

```python
#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI

net = Mininet(switch=OVSSwitch, controller=None)
s1  = net.addSwitch('s1', failMode='standalone')
for i in range(1, 5):
    net.addLink(net.addHost(f'h{i}'), s1)
net.start(); CLI(net); net.stop()
```

### T2 — Linear com gargalo (aciona AQM CoDel)

```python
#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
s1  = net.addSwitch('s1', failMode='standalone')
s2  = net.addSwitch('s2', failMode='standalone')
for i in range(1, 3):
    net.addLink(net.addHost(f'h{i}'), s1, bw=100)
    net.addLink(net.addHost(f'h{i+2}'), s2, bw=100)
net.addLink(s1, s2, bw=10, max_queue_size=50)   # gargalo — AQM ativo aqui
net.start(); CLI(net); net.stop()
```

### T3 — Dumbbell (ECN clássico)

```python
#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
sl  = net.addSwitch('sl', failMode='standalone')
sr  = net.addSwitch('sr', failMode='standalone')
for i in range(1, 4):
    net.addLink(net.addHost(f's{i}', ip=f'10.0.1.{i}/24'), sl, bw=100)
    net.addLink(net.addHost(f'r{i}', ip=f'10.0.2.{i}/24'), sr, bw=100)
net.addLink(sl, sr, bw=10, delay='2ms', max_queue_size=100)
net.start(); CLI(net); net.stop()
```

### T4 — PolKA linear (3 switches)

```python
#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from polka_switch import PolkaSwitch

net = Mininet(controller=None, link=TCLink)
s1  = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
s2  = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
s3  = net.addSwitch('s3', cls=PolkaSwitch, nodeId='0x0589')
h1  = net.addHost('h1', ip='10.0.0.1/24')
h2  = net.addHost('h2', ip='10.0.0.2/24')
net.addLink(h1, s1); net.addLink(s1, s2)
net.addLink(s2, s3); net.addLink(s3, h2)
net.start(); CLI(net); net.stop()
```

### T5 — PolKA + ECN (source routing com AQM)

```python
#!/usr/bin/env python3
"""PolKA + ECN: source routing com marcação CE automática no gargalo."""
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from polka_switch import PolkaSwitch

net = Mininet(controller=None, link=TCLink)
s1  = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
s2  = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
h1  = net.addHost('h1', ip='10.0.0.1/24')
h2  = net.addHost('h2', ip='10.0.0.2/24')
net.addLink(h1, s1, bw=100)
net.addLink(s1, s2, bw=10, max_queue_size=100)   # gargalo + AQM
net.addLink(s2, h2, bw=100)
net.start()
# Habilitar ECN nos hosts (tráfego IP interno ao payload PolKA)
h1.cmd('sysctl -w net.ipv4.tcp_ecn=1')
h2.cmd('sysctl -w net.ipv4.tcp_ecn=1')
CLI(net); net.stop()
```

---

## 9. Matriz de Cenários

### Dimensões de configuração

| Dim. | Opções |
|---|---|
| **A — Modo switch** | A1 standalone · A2 secure+flows · A3 secure+ECN-match · A4 PolKA |
| **B — ECN IP** | B0 Not-ECT · B1 ECT(0) · B2 ECT(1)/L4S · B3 misto |
| **C — TCP ECN** | C0 off · C1 on (inicia) · C2 passivo · C3 AccECN |
| **D — Topologia** | D1 single · D2 gargalo · D3 árvore · D4 dumbbell · D5 delay · D6 PolKA linear |

**Total: 4 × 4 × 4 × 6 = 384 combinações possíveis.**

### Cenários representativos

| Cenário | Switch | ECN IP | TCP ECN | Topologia | Comportamento |
|---|---|---|---|---|---|
| **S01** | A1 | B0 | C0 | D1 | Sem ECN; forwarding L2 puro |
| **S02** | A1 | B1 | C1 | D1 | ECN habilitado; sem congestionamento |
| **S03** | A1 | B1 | C1 | D2 | **CoDel ativo**: CE marcado no gargalo |
| **S04** | A1 | B2 | C1 | D2 | L4S (ECT(1)) + CoDel |
| **S05** | A1 | B3 | C0/C1 | D2 | Misto: ECT recebe CE, Not-ECT descartado |
| **S06** | A1 | B1 | C3 | D4 | AccECN rastreado no conntrack |
| **S07** | A2 | B0 | C0 | D2 | Flows estáticos sem ECN |
| **S08** | A2 | B1 | C1 | D2 | Flows estáticos + CoDel |
| **S09** | A3 | B1 | C1 | D2 | Flows com match `nw_ecn` + CoDel |
| **S10** | A3 | B2 | C1 | D4 | L4S flows separados + AccECN |
| **S11** | A3 | B3 | C1/C2 | D3 | Árvore com tratamento ECT/Not-ECT diferenciado |
| **S12** | A1 | B1 | C2 | D5 | Delay alto → sojourn > 5 ms → CoDel dispara |
| **S13** | A1 | B1 | C1 | D4 | Múltiplos fluxos; CoDel por porta |
| **S14** | A2 | B2 | C3 | D4 | **ECN completo**: L4S + AccECN + CoDel |
| **S15** | A4 | B0 | C0 | D6 | **PolKA puro**: source routing sem ECN |
| **S16** | A4 | B1 | C1 | D6 | **PolKA + ECN**: source routing + CoDel |
| **S17** | A4 | B2 | C3 | D6 | **PolKA + L4S + AccECN**: cenário máximo |

---

## 10. Exemplos Completos

### S03 — Gargalo com ECN clássico e AQM CoDel

```python
#!/usr/bin/env python3
"""S03: ECT(0) + TCP ECN + gargalo 10 Mbps. CoDel marca CE em vez de descartar."""
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def run():
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
    sl = net.addSwitch('sl', failMode='standalone')
    sr = net.addSwitch('sr', failMode='standalone')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    net.addLink(h1, sl, bw=100)
    net.addLink(h2, sr, bw=100)
    net.addLink(sl, sr, bw=10, max_queue_size=100)
    net.start()
    for h in (h1, h2):
        h.cmd('sysctl -w net.ipv4.tcp_ecn=1 net.ipv4.tcp_ecn_fallback=0')
    print("h2 iperf3 -s &  |  h1 iperf3 -c 10.0.0.2 -t 30 -b 50M")
    print("sh ovs-dpctl dump-conntrack   # ecn=confirmed")
    print("sh ovs-appctl coverage/show   # aqm_ce_marked")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
```

### S14 — Completo: L4S + AccECN + CoDel

```python
#!/usr/bin/env python3
"""S14: ECT(1) + AccECN + CoDel + dumbbell — cenário ECN mais completo."""
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

HOST_SETUP = """
sysctl -w net.ipv4.tcp_ecn=1 net.ipv4.tcp_ecn_fallback=0
tc qdisc add dev {intf} root handle 1: prio 2>/dev/null || true
tc filter add dev {intf} parent 1: protocol ip u32 match ip tos 0x00 0xff \
   action pedit ex munge ip tos set 0x01 2>/dev/null || true
"""

def run():
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
    sl = net.addSwitch('sl', failMode='standalone')
    sr = net.addSwitch('sr', failMode='standalone')
    senders   = [net.addHost(f's{i}', ip=f'10.0.1.{i}/24') for i in range(1, 4)]
    receivers = [net.addHost(f'r{i}', ip=f'10.0.2.{i}/24') for i in range(1, 4)]
    for h in senders:
        net.addLink(h, sl, bw=100)
    for h in receivers:
        net.addLink(h, sr, bw=100)
    net.addLink(sl, sr, bw=10, delay='1ms', max_queue_size=200)
    net.start()
    for h in senders + receivers:
        h.cmd(HOST_SETUP.format(intf=h.defaultIntf().name))
    print("r1 iperf3 -s &  |  s1 iperf3 -c 10.0.2.1 -t 60 -b 20M &")
    print("sh ovs-dpctl dump-conntrack   # ecn=accecn")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
```

### S15 — PolKA puro (source routing sem ECN)

```python
#!/usr/bin/env python3
"""S15: 3 switches PolKA em série. Pacotes etherType 0x1234 roteados por CRC-16."""
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from polka_switch import PolkaSwitch

def run():
    setLogLevel('info')
    net = Mininet(controller=None, link=TCLink)
    s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
    s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
    s3 = net.addSwitch('s3', cls=PolkaSwitch, nodeId='0x0589')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, h2)
    net.start()
    print("Enviar pacote PolKA com Scapy no h1:")
    print("  from scapy.all import *")
    print("  rid = b'\\x00'*18 + b'\\x03\\x02'")
    print("  sendp(Ether(type=0x1234)/Raw(load=rid)/IP(dst='10.0.0.2'), iface='h1-eth0')")
    print("Verificar: sh ovs-dpctl dump-flows | grep 0x1234")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
```

### S17 — PolKA + L4S + AccECN (cenário máximo)

```python
#!/usr/bin/env python3
"""S17: PolKA + ECT(1) + AccECN + CoDel — todos os recursos combinados."""
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from polka_switch import PolkaSwitch

HOST_SETUP = """
sysctl -w net.ipv4.tcp_ecn=1 net.ipv4.tcp_ecn_fallback=0
tc qdisc add dev {intf} root handle 1: prio 2>/dev/null || true
tc filter add dev {intf} parent 1: protocol ip u32 match ip tos 0x00 0xff \
   action pedit ex munge ip tos set 0x01 2>/dev/null || true
"""

def run():
    setLogLevel('info')
    net = Mininet(controller=None, link=TCLink)
    s1 = net.addSwitch('s1', cls=PolkaSwitch, nodeId='0x8005')
    s2 = net.addSwitch('s2', cls=PolkaSwitch, nodeId='0x1021')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    net.addLink(h1, s1, bw=100)
    net.addLink(s1, s2, bw=10, delay='2ms', max_queue_size=150)  # gargalo + AQM
    net.addLink(s2, h2, bw=100)
    net.start()
    for h in (h1, h2):
        h.cmd(HOST_SETUP.format(intf=h.defaultIntf().name))
    print("Enviar tráfego PolKA com payload IP+TCP (Scapy) e verificar:")
    print("  sh ovs-appctl coverage/show | grep aqm")
    print("  sh ovs-dpctl dump-conntrack | grep ecn")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
```

---

## 11. Verificação e Diagnóstico

### Estado ECN no conntrack

```bash
ovs-dpctl dump-conntrack

# Campo ecn= na saída:
#   ecn=init       → SYN com ECE+CWR visto
#   ecn=confirmed  → ECN confirmado via SYN-ACK
#   ecn=accecn     → AccECN negociado (bit AE)
```

### Contadores AQM

```bash
ovs-appctl coverage/show | grep -E "aqm_ce_marked|aqm_drop_not_ect|aqm_codel_enter"
```

### Flows PolKA no datapath userspace

```bash
# No datapath=netdev (userspace), flows PolKA aparecem no DPCLS:
ovs-dpctl dump-flows | grep "dl_type=0x1234"
# No datapath de kernel, megaflows para 0x1234 não são instalados —
# cada pacote PolKA vai ao slow-path (upcall) para roteamento correto por routeId.
```

### Trace do pipeline

```bash
# ECN — simular pacote ECT(0) entrando pela porta 1:
ovs-appctl ofproto/trace s1 "in_port=1,ip,nw_ecn=2,nw_src=10.0.0.1,nw_dst=10.0.0.2"

# PolKA — simular pacote PolKA entrando pela porta 1:
ovs-appctl ofproto/trace s1 "in_port=1,dl_type=0x1234,dl_dst=ff:ff:ff:ff:ff:ff"
```

### Inspecionar bits ECN no tráfego

```bash
tcpdump -i s1-eth1 -v 'tcp' 2>&1 | grep -E "tos|ECN|CE|ECT"
# tos 0x3 → CE marcado (0b11)
# tos 0x2 → ECT(0)    (0b10)
# tos 0x1 → ECT(1)    (0b01)
```

### ECN negociado no host

```bash
# Dentro do CLI Mininet:
h1 ss -tin dst 10.0.0.2
# Linha "ecn" na saída indica negociação bem-sucedida
```

---

## 12. Referência Rápida de Comandos

```bash
# === Build e inicialização ===
cd ovs/ && ./boot.sh && ./configure && make -j$(nproc) && sudo make install
sudo /usr/share/openvswitch/scripts/ovs-ctl start

# === Modos do switch ===
ovs-vsctl set-fail-mode s1 standalone          # aprendizado L2
ovs-vsctl set-fail-mode s1 secure              # somente flows manuais

# === Configurar PolKA ===
ovs-vsctl set Bridge s1 other_config:polka-node-id=0x8005
ovs-vsctl get Bridge s1 other_config           # verificar

# === Flows ECN (modo secure) ===
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=1,action=normal"  # ECT(1)
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=2,action=normal"  # ECT(0)
ovs-ofctl add-flow s1 "priority=200,ip,nw_ecn=3,action=normal"  # CE
ovs-ofctl add-flow s1 "priority=100,ip,nw_ecn=0,action=normal"  # Not-ECT
ovs-ofctl add-flow s1 "priority=1,action=normal"                 # resto

# === sysctl ECN nos hosts ===
sysctl -w net.ipv4.tcp_ecn=0    # desabilitado
sysctl -w net.ipv4.tcp_ecn=1    # habilitado (inicia + aceita)
sysctl -w net.ipv4.tcp_ecn=2    # passivo (só aceita)

# === Diagnóstico ===
ovs-appctl coverage/show | grep aqm        # contadores AQM
ovs-dpctl dump-conntrack                   # estado ECN por conexão
ovs-dpctl dump-flows | grep 0x1234         # flows PolKA
ovs-ofctl dump-ports s1                    # contadores por porta
ovs-ofctl dump-flows s1                    # regras OpenFlow

# === Mininet sem controlador ===
sudo mn --switch ovsk --controller none --topo linear,2 --link tc,bw=10
```

---

## Resumo das Combinações

```
Modo switch:   A1 standalone | A2 secure+flows | A3 secure+ECN | A4 PolKA
                      ×
ECN IP:        B0 Not-ECT | B1 ECT(0) | B2 ECT(1)/L4S | B3 misto
                      ×
TCP ECN:       C0 off | C1 on | C2 passivo | C3 AccECN
                      ×
Topologia:     D1 single | D2 gargalo | D3 árvore | D4 dumbbell | D5 delay | D6 PolKA

= 4 × 4 × 4 × 6 = 384 combinações (17 cenários representativos documentados acima)
```

**Guia rápido de escolha:**

| Objetivo | Cenário recomendado |
|---|---|
| Teste básico de conectividade | **S01** |
| Validar AQM CoDel em ação | **S03** ou **S13** |
| Tráfego misto ECN / não-ECN | **S05** ou **S11** |
| Controle fino por flow OpenFlow | **S09** |
| ECN + L4S + AccECN completo | **S14** |
| Source routing PolKA básico | **S15** |
| PolKA + ECN + AQM combinados | **S16** ou **S17** |
