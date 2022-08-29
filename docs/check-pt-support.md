## Code snippet to check whether your CPU supports Intel PT 

Simply download, compile, and run the following C code in your system.

```
#include <stdio.h>
#define BIT_MASK(x) (1ULL << x)

int main(){
    int a = 0x7, b, c = 0, d;
    __asm__(
        "cpuid \n\t"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "0"(a), "2"(c)
    );

    if((b & BIT_MASK(25)) == 0){
        printf("Intel PT not supported.\n");
    }
    else{
        printf("Intel PT supported.\n");
    }
    return 0;
}
```