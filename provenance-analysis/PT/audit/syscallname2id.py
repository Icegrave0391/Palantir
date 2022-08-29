def main():
    f = open('syscall_id.txt')

    for line in f.readlines():
        tokens = line.split()
        id = tokens[0]
        name = tokens[1]
        # print('syscall_map[\"' + name + '\"] = SyscallType_t::' + name.upper()
        # + ';')
        
        print('case SyscallType_t::' +  name.upper() + ": {")
        print('\treturn ' + id + ';\n}')

    f.close()

if __name__ == '__main__':
    main()