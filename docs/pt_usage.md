# PT Tracing

## Collect PT traces without metadata (memory information)

1. Define the program to monitor:
```bash
sudo su
echo -n wget > /sys/kernel/debug/pt_monitor
wget www.google.com
```

2. Collect PT trace
```bash
cp /var/log/pt.log pt.log
```

3. Stop PT tracing
```bash
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor
```

## Collect PT traces with metadata (e.g., memory information). 

Our PT tracing is built atop [ARCUS](https://github.com/carter-yagemann/ARCUS).
Also, note that the following commands need the `sudo` privilege, in which case python is the root user's python3 environment.

1. Start PT tracing

```bash
cd runtime-monitoring/trace
sudo python tracer.py trace_output wget www.google.com
```

2. Stop PT tracing and collect PT traces

```bash
cd runtime-monitoring/trace
sudo python tracer.py --collect trace_output wget www.google.com
```
