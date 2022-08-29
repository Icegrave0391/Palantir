import json
import collections
import sys

def main():
    events = {}

    if len(sys.argv) < 2:
        exit("Do not define audit file")

    f = open(sys.argv[1])

    for log in f.readlines():
        data = json.loads(log)

        seq = int(data['auditd']['sequence'])
        syscall = data['auditd']['data']['syscall']

        events[seq] = syscall

    od = collections.OrderedDict(sorted(events.items()))

    for idx, e in enumerate(od):
        print(idx, e, od[e])

    f.close()

if __name__ == '__main__':
    main()