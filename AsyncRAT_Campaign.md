# AsyncRAT Campaign Analysis: Infrastructure Patterns, IoCs, and Operational Insights

## Overview

This report documents the analysis of multiple samples associated with AsyncRAT, a widely used open-source remote access trojan (RAT) frequently leveraged in commodity malware campaigns.

The objective of this research was to:

- Extract and validate network-based Indicators of Compromise (IoCs)
- Identify infrastructure patterns across samples
- Evaluate consistency in operator tradecraft

All data presented here reflects static analysis of 100 samples using a custom extraction tool.

## Key Findings

### Infrastructure Reuse

Analysis revealed strong domain clustering, with threat actors reusing base domains and segmenting activity via subdomains.

Examples:

- teammambaperth.com  
- javhd.co.uk  
- jvrakia.com  

Each domain hosts multiple subdomains tied to different malware families or campaign labels.

### Thematic Subdomain Naming

Subdomains frequently reference well-known malware families:

- ryuk.teammambaperth.com  
- locky.javhd.co.uk  
- formbook.javhd.co.uk  
- azorult.teammambaperth.com  

This pattern suggests:

- Campaign labeling by operators  
- Internal segmentation or tracking  
- Reuse of infrastructure across multiple campaigns  

### Network Configuration

Across samples:

- **Ports observed:** 80, 443  
- **Protocol:** HTTP/HTTPS-based C2  
- **Fallback mechanisms:** Not observed  

This indicates a preference for blending with legitimate web traffic.

## Extracted IoCs

### Domains

```
teammambaperth.com
www.teammambaperth.com
ryuk.teammambaperth.com
downadup.teammambaperth.com
gh0st.teammambaperth.com
azorult.teammambaperth.com
javhd.co.uk
www.javhd.co.uk
industroyer.javhd.co.uk
locky.javhd.co.uk
formbook.javhd.co.uk
jvrakia.com
www.jvrakia.com
triton.jvrakia.com
client.jvrakia.com
lokibot.jvrakia.com
malware.jvrakia.com
smalltimes.com
xl365.livebytexscore.com
```

### Campaign Identifiers
ECeDRSA3bolG
6I1A2I5KBH4Q
5Q2ZsaDMmVnm

