#ifndef _PT_DRIVER_H_
#define _PT_DRIVER_H_

#include <cstdio>
#include <bits/stdc++.h>
#include <chrono>

extern "C" {
    #include "pt.h"
}

#include "../taint/common.h"

#define PT_RING_BUFFER_SIZE 2048

#define print(str) std::cout << str << std::endl

#endif
