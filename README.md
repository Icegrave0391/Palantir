# PalanTir

We present PalanTir, a provenance-based system that enhances system observability
to enable precise and scalable attack investigation.

> PalanTir: Optimizing Attack Provenance with Hardware-enhanced System Observability. CCS'22


## System Environment

PalanTir runs on the 16.04.6 LTS Ubuntu Linux 64-bit distribution. You should
install this distro before proceeding.

**Hardware Requirement:** 
A physical machine with an [Intel PT](https://www.intel.com/content/www/us/en/support/articles/000056730/processors.html) supported CPU. 
To know whether your current CPU supports Intel PT, please refer to our [document](docs/check-pt-support.md).

## Installation

- [Static Binary Analysis Setup](docs/static-analysis-setup.md)

- [System Auditing Setup](docs/audit_setup.md)

- [PT Tracing Setup](docs/pt_setup.md)

- [Provenance Setup](docs/provenance_setup.md)

## Usage

- [Static Binary Analysis](docs/static-analysis.md)

- [System Auditing](docs/audit_usage.md)

- [PT Tracing](docs/pt_usage.md)

- [Attack Provenance](docs/provenance_usage.md)

## Reproducibility
To facilitate future research, we will provide our evaluation data in the
final version. Our evaluation logs can be found under `log`.
