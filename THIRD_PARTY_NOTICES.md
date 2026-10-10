# Third-party notices

English | [Русский](THIRD_PARTY_NOTICES-RU.md)

DurkaHelper's own code is licensed under the [MIT License](LICENSE). Third-party projects, copied examples and references retain their own terms and attribution.

| Component | Provenance |
|---|---|
| S4DFarm | [Pinned source](https://github.com/C4T-BuT-S4D/S4DFarm/tree/3b8b057c95e0467c6afb3a47648e8b6befd1a815) |
| Neo | [Pinned server source](https://github.com/C4T-BuT-S4D/neo/tree/2f2a4eb63f9715155844284f253ba786d330c9ae), release v2.4.2 as recorded in the lock |
| Packmate | [Pinned source](https://gitlab.com/packmate/Packmate/-/tree/938031f1dedfbedabef5b049368ed5b6ba6a900a); upstream code is not modified by the deployment overlay |
| Container/runtime dependencies | Exact identities in [toolchain lock](config/toolchain.lock.json) and [integration image lock](config/integration-images.lock.json) |
| A/D case studies and API documentation | Source links and attribution retained in the [catalog](docs/vulnerabilities/README.md) |

A source checkout, container image or cached package is not automatically cleared for redistribution. Before publishing an offline external-toolchain bundle, inventory its licenses, notices, source-offer obligations and permission to distribute binaries. Keep Docker Desktop licensing/installation subject to the operator's applicable terms; it is not redistributed by DurkaHelper.

The artifact tool records declared provenance/license metadata but does not make a legal determination. Until review is complete, external caches and image exports remain private operator artifacts. Do not remove attribution while anonymizing operator-specific data.
