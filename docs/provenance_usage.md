# Parsing audit logs

The provenance graph is a common representation of audit logs. The nodes in the
graph represent system entities (e.g., processes, files, sockets) and edges
represent system calls in the direction of information flow.
We currently support parsing audit logs in Auditbeat's json format.

Make Sure you have successfully complied driverbeat under `provenance-analysis/AUDIT/parse`. 
We run the following examples on a Ubuntu desktop with Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz.

Test case: Parse audit logs collected from the watering hole attack.

```bash
cd provenance-analysis/AUDIT/parse
./driverbeat -trace ../../../runtime-monitoring/audit/watering_hole/
```

Expected Result:

```
Processing Dir: ../audit/watering_hole/
beat file: ../audit/watering_hole/auditbeat.-1
recover process info
Reduce noisy events
	collecting temporary file
	collecting ShadowFileEdge
	collecting ShadowProcEdge
	collecting MissingEdge
	collecting Library
	deleting noisy events
Reduce Noise Events runtime overhead: 0.0181046

KG construction runtime overhead: 65.4125

KG Statistics
#Events: 2934643
#Edge: 5873
#Noisy events: 9144
#Proc: 612
#File: 2428
#Socket: 110
#Node: 3150
#Node(3150) = #Proc(612) + #File(2428) + #Socket(110)
```

# Parsing Intel PT

We use distorm to disassemble PT trace. Our PT parser is built atop Griffin's
implementation of fast disassembly lookup.

Test case: Parse PT traces collected from `wget` in the watering hole attack.

```bash
cd provenance-analysis/PT/pt
./driver ../../../runtime-monitoring/trace/watering_hole_wget_1-20/trace.file
```

Expected Result:

```
process: tgid=3500, cmd=wget
thread: tgid=3500, pid=3500, name=wget
#Block 685999
#Instruction 6534846
#Packet 162578
Disassembly Runtime 0.025 seconds
```

# Taint on PT trace and Feedback fine-grained provenance back to audit logs

We use Redis to store all the taint summaries. Before performing taint analysis,
we first need to load taint summaries from a local file to Redis using

```bash
cd PalanTir/PT/tools/redis
<  db/wget_1-20_db0.json redis-load -u 127.0.0.1:6379
```

Test case: Propagate taints on PT traces collected from `wget` in the watering
hole attack, and feedback instruction-level provenance to the audit logs of the watering
hole attack.

```bash
cd provenance-analysis/PT
./driver wget_1-20 ../../runtime-monitoring/trace/watering_hole_wget_1-20/trace.file ../../runtime-monitoring/audit/watering_hole/
```

Expected Result:

```
PT analysis on wget_1-20
succeed to open ../../AUDIT/audit/watering_hole/auditbeat.-1
Successfully Connect to Redis db
plt address range: 403fc0 -> 404e30
hook address: 4402d2 4402c7 4402fa 4402f8 4402e5 4402b8 4402e0 4402b0 44024a 440276 44023f 44027b 440265 440288 44022b 440260 440220 4401e1 4401d0 4401cb 4401dd 4401c6 4401d8 4401be 4401b9 4401b0 440344 44033f 44033a 440332 440349 440320 440309 440300 440189 440181 44018b 440170 440165 440163 44015e 440159 440150 
Geting all taint summaries
Initing adj_map_forward
Initing adj_map
Initing taint summary in adj_map
process: tgid=12594, cmd=wget
thread: tgid=12594, pid=12594, name=wget
#Instruction 1329321333
#Packet 62175669
Tree Construction Overhead 7.718 seconds
PT Disassembly Overhead 1.098 seconds
PT Taint/Traverse Overhead 12.556 seconds
PT Taint Overhead 0.086 seconds
Feedback taint to audit logs
#Logs10265
process: 12594
#audit logs is 10265
#pt syscalls is 10382

PG Tag Overhead 0.162 seconds
```
