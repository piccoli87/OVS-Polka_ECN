# OpenVSwitch com suporte ECN e POLKA

 ---
  ## Open vSwitch Estendido — ECN/AccECN, AQM CoDel e PolKA

  Este projeto é um fork do Open vSwitch (OVS) que estende o switch virtual com três conjuntos de funcionalidades para pesquisa em redes programáveis e gerenciamento de congestionamento. Todas as extensões operam sem necessidade de controlador OpenFlow, mantendo o switch autônomo.

  ---
  ## ECN e AccECN (RFC 3168 / RFC 9331)

  O plano de dados e o módulo de rastreamento de conexões (conntrack) foram modificados para suporte completo a Explicit Congestion Notification. Novos helpers em lib/packets.h/c identificam os codepoints ECN no campo DS do IP — Not-ECT, ECT(0), ECT(1)/L4S e CE — e marcam o bit CE de forma segura somente em pacotes ECN-capazes. O conntrack-tcp.c rastreia o handshake TCP por conexão, registrando três estados: ecn=init (SYN com ECE+CWR), ecn=confirmed (ECN clássico confirmado) e ecn=accecn (AccECN negociado via bit AE/NS no SYN). O estado ECN é exposto na API pública de conntrack via CT_DPIF_ECN_*.

  ---
  ## AQM CoDel (RFC 8289)

  Implementado inteiramente no espaço de usuário (PMD), o algoritmo CoDel opera por porta TX e entra em ação automaticamente, sem configuração extra. O critério de disparo é baseado no sojourn time do batch de pacotes: se o tempo de permanência na fila superar o alvo de 5 ms por mais de 100 ms consecutivos, o AQM age de forma diferenciada — pacotes ECN-capazes (ECT(0) ou ECT(1)) recebem a marcação CE sem descarte, enquanto pacotes Not-ECT são descartados. O AQM só atua com batches de dois ou mais pacotes para evitar que o array de envio fique completamente vazio. Contadores de diagnóstico (aqm_ce_marked, aqm_drop_not_ect) ficam disponíveis via ovs-appctl coverage/show.

  ---
  ## PolKA — Source Routing por CRC-16

  A extensão PolKA (Polynomial Key-based Architecture) implementa roteamento na origem sem tabela de rotas distribuída. Cada pacote carrega um campo routeId de 160 bits no cabeçalho Ethernet (etherType 0x1234). Em cada switch, a porta de saída é computada localmente por:

  porta = CRC16(routeId[0..17], nodeId) XOR routeId_u16(bytes 18–19)

  O nodeId é o polinômio CRC-16 único do nó, configurado via other_config:polka-node-id. Para garantir o roteamento correto, o encaminhamento PolKA é stateless por design: megaflows para etherType 0x1234 são proibidos de serem instalados no datapath, forçando cada pacote ao slow-path (upcall) onde xlate_polka() lê os bytes brutos do routeId e computa o próximo salto. O switch lê a configuração polka-node-id em vswitchd/bridge.c e a propaga até a camada de tradução de fluxos (ofproto-dpif-xlate.c).

  ---
  ## Integração e Topologias
  
  As três extensões são ortogonais e combináveis: PolKA pode transportar payloads IP com ECN habilitado, e o AQM CoDel atua em todas as portas TX, incluindo tráfego PolKA. O repositório inclui o helper. Python polka_switch.py (classe PolkaSwitch para Mininet) e cinco topologias de referência — de um switch isolado até o cenário máximo PolKA + L4S + AccECN + CoDel em topologia dumbbell. A matriz de configuração cobre 4 modos de switch × 4 codepoints ECN × 4 modos TCP × 6 topologias, totalizando 384 combinações documentadas, com 17 cenários representativos detalhados.


## Pré-requisitos e Build

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
