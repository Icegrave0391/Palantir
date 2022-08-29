# PT Tracing Setup

## Install Linux Kernel

We developed a [Linux kernel](../linux/) built on Linux 4.2 to collect program execution traces collected by Intel PT. 
To install the kernel module, you need to run the following commands.

```bash
# Please download this repo first
cd /path/to/linux
cp config .config
make INSTALL_MOD_STRIP=1 -j$(nproc)
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make INSTALL_MOD_STRIP=1 install
```

Note: You need to install Auditbeat in this kernel to start system auditing.

## Install PT Trace Collector

The PT Trace collection python script is [tracer.py](../runtime-monitoring/trace/tracer.py). You need the root privilege (sudo) to run the script.
In such a case, all the requirements should be installed in the root user's python environment.

The following installation commands assume the pip is under the root user's environment (root's python3).

```bash
cd runtime-monitoring/trace
pip install -r requirements.txt
```