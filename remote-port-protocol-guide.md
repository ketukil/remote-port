# Remote Port Protocol

Remote-Port (RP) is an inter-simulator protocol that enables communication between different simulation environments. It provides a reliable point-to-point communication channel between simulators, allowing them to exchange commands and data.

## Protocol Overview

<div style="text-align: center;">
<em>Figure 1: Remote Port Protocol Communication Stack</em>


```mermaid
flowchart TB
    classDef highlightBox stroke:#333,stroke-width:1px;
    classDef socketsLayer stroke:#333,stroke-width:1px;
    classDef protocolLayer stroke:#333,stroke-width:1px;
    classDef tlmLayer stroke:#333,stroke-width:1px;
    classDef componentLayer stroke:#333,stroke-width:1px;
    
    subgraph Layer["Protocol Stack"]
        direction TB
        C[SystemC Components<br>PCI-E EP, Memory, Wires, ATS] -..- T
        T[TLM Adaptors<br>Memory Master/Slave, Wires, ATS] -..- R
        R[Remote Port Protocol<br>Encoding/Decoding, Packets] -..- S
        S[Socket Layer<br>UNIX, TCP, TCPD] -..- D[Physical Communication Layer]
    end
    
    C:::componentLayer
    T:::tlmLayer
    R:::protocolLayer
    S:::socketsLayer
    Layer:::highlightBox
```
</div>

## Communication Flow

<div style="text-align: center;">
<em>Figure 2: Remote Port Session Establishment</em>

```mermaid
sequenceDiagram
    participant SimA as Simulator A
    participant SimB as Simulator B
    
    SimA->>SimB: HELLO Packet (version, capabilities)
    SimB->>SimA: HELLO Packet (version, capabilities)
    Note over SimA,SimB: Capabilities negotiation
    opt Configuration Phase
        SimA->>SimB: CFG Packet (optional)
        SimB->>SimA: CFG Packet (optional)
    end
    Note over SimA,SimB: Session established
    
    loop Command Exchange
        SimA->>SimB: Command Packet
        alt Requires Response
            SimB->>SimA: Response Packet
        else Posted Command (no response)
            Note over SimB: Process command
        end
    end
```
</div>

## Packet Structure

<div style="text-align: center;">
<em>Figure 3: Remote Port Packet Format</em>

```mermaid
classDiagram
    class RPPacket {
        RPHeader header
        Payload payload
        Data data (optional)
    }
    
    class RPHeader {
        uint32_t cmd
        uint32_t len
        uint32_t id
        uint32_t flags
        uint32_t dev
    }
    
    RPPacket *-- RPHeader
    
    note for RPHeader "flags:<br>- optional<br>- response<br>- posted"
```
</div>

## Key Commands & Data Flow

<div style="text-align: center;">
<em>Figure 4: Remote Port Command Types</em>

```mermaid
graph TD
    RP[Remote Port Commands]
    RP -->|"RP_CMD_hello (1)"| HELLO[Hello Command<br>Version & Capabilities Exchange]
    RP -->|"RP_CMD_cfg (2)"| CFG[Configuration Command]
    RP -->|"RP_CMD_read (3)<br>RP_CMD_write (4)"| MEM[Memory Access Commands]
    RP -->|"RP_CMD_interrupt (5)"| INT[Interrupt Command]
    RP -->|"RP_CMD_sync (6)"| SYNC[Synchronization Command]
    RP -->|"RP_CMD_ats_req (7)<br>RP_CMD_ats_inv (8)"| ATS[Address Translation Service]
    
    classDef cmdClass stroke:#666,stroke-width:1px;
    classDef mainNode stroke:#666,stroke-width:1px;
    
    RP:::mainNode
    HELLO:::cmdClass
    CFG:::cmdClass
    MEM:::cmdClass
    INT:::cmdClass
    SYNC:::cmdClass
    ATS:::cmdClass
```
</div>


## Synchronization Model

<div style="text-align: center;">
<em>Figure 5: Synchronization Between Simulators</em>

```mermaid
sequenceDiagram
    participant SimA as Simulator A (clk=100)
    participant SimB as Simulator B (clk=150)
    
    Note over SimA,SimB: Time synchronization ensures coherent simulation
    
    SimA->>SimB: SYNC Command (timestamp=100)
    SimB->>SimA: SYNC Response (timestamp=150)
    Note over SimA: Account for time difference
    
    SimA->>SimB: WRITE Command (timestamp=120)
    Note over SimB: Process at timestamp=120
    SimB->>SimA: WRITE Response (timestamp=170)
    
    Note over SimA,SimB: Quantum keepers manage time synchronization
```
</div>

## Bus Access Protocol

<div style="text-align: center;">
<em>Figure 6: Memory Access Command Flow</em>


```mermaid
sequenceDiagram
    participant Master
    participant RemotePort
    participant Target
    
    Master->>RemotePort: TLM Read/Write Transaction
    RemotePort->>Target: RP_CMD_read/write Packet
    Note over Target: Process memory access
    alt If not posted
        Target->>RemotePort: Response Packet
        RemotePort->>Master: TLM Transaction Response
    else If posted
        Note over Target: No response required
    end
```
</div>

## Capabilities and Extensions

The Remote Port protocol supports various capabilities that can be negotiated during the HELLO packet exchange:

<div style="text-align: center;">
<em>Figure 7: Remote Port Capabilities</em>

```mermaid
graph LR
    CAP[Capabilities]
    CAP --> BUSEXT[CAP_BUSACCESS_EXT_BASE<br>Extended header layout]
    CAP --> BYTEENABLE[CAP_BUSACCESS_EXT_BYTE_EN<br>Byte enables support]
    CAP --> WIREUPDATES[CAP_WIRE_POSTED_UPDATES<br>Posted wire updates]
    CAP --> ATSCAP[CAP_ATS<br>Address Translation Services]
    
    classDef mainCap stroke:#333,stroke-width:1px;
    classDef capClass stroke:#333,stroke-width:1px;
    
    CAP:::mainCap
    BUSEXT:::capClass
    BYTEENABLE:::capClass
    WIREUPDATES:::capClass
    ATSCAP:::capClass
```
</div>

## Implementation Architecture

<div style="text-align: center;">
<em>Figure 8: Remote Port Component Architecture</em>

```mermaid
graph TB
    RP[remoteport_tlm]
    RP -->|"manages devices"| DEV[remoteport_tlm_dev]
    
    DEV -->|"memory access"| MM[remoteport_tlm_memory_master]
    DEV -->|"memory mapping"| MS[remoteport_tlm_memory_slave]
    DEV -->|"interrupt signals"| W[remoteport_tlm_wires]
    DEV -->|"address translation"| ATS[remoteport_tlm_ats]
    
    RP -.->|"socket communication"| SOCK[Socket Layer<br>UNIX, TCP]
    RP -.->|"synchronization"| SYNC[Synchronization<br>loosely_timed / untimed]
    
    classDef mainClass stroke:#333,stroke-width:1px;
    classDef devClass stroke:#333,stroke-width:1px;
    classDef supportClass stroke:#333,stroke-width:1px;
    
    RP:::mainClass
    DEV:::mainClass
    MM:::devClass
    MS:::devClass
    W:::devClass
    ATS:::devClass
    SOCK:::supportClass
    SYNC:::supportClass
```
</div>

## Protocol Use Case: PCI-E Device

<div style="text-align: center;">
<em>Figure 9: Remote Port PCI-E Endpoint Example</em>

```mermaid
graph TB
    PCIE[Remote Port PCI-E Endpoint]
    
    PCIE -->|"Configuration"| CFG[Config Space Socket]
    PCIE -->|"Memory/IO"| BAR[BAR Sockets]
    PCIE -->|"DMA"| DMA[DMA Socket]
    PCIE -->|"Interrupts"| IRQ[IRQ Signals]
    PCIE -->|"Address Translation"| ATS[ATS Req/Inv Sockets]
    
    subgraph RP_DEVS[Remote Port Devices]
        direction TB
        RP_CFG[rp_config]
        RP_IO[rp_io]
        RP_MMIO[rp_mmio]
        RP_DMA[rp_dma]
        RP_IRQ[rp_irq]
        RP_ATS[rp_ats]
    end
    
    CFG --- RP_CFG
    BAR --- RP_IO
    BAR --- RP_MMIO
    DMA --- RP_DMA
    IRQ --- RP_IRQ
    ATS --- RP_ATS
    
    classDef pcieClass stroke:#333,stroke-width:1px;
    classDef ifClass stroke:#333,stroke-width:1px;
    classDef rpClass stroke:#333,stroke-width:1px;
    
    PCIE:::pcieClass
    CFG:::ifClass
    BAR:::ifClass
    DMA:::ifClass
    IRQ:::ifClass
    ATS:::ifClass
    RP_DEVS:::rpClass
```
</div>

## Protocol Version and Compatibility

The Remote Port protocol uses a versioning scheme with major and minor version numbers. The current protocol version is 4.3.

- Major version changes indicate backward-incompatible modifications
- Minor version changes indicate backward-compatible additions

Simulators must exchange and verify version compatibility during the HELLO packet exchange.