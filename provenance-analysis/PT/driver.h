#ifndef _PT_DRIVER_H_
#define _PT_DRIVER_H_

#include <cstdio>
#include <bits/stdc++.h>
#include <chrono>

extern "C" {
    #include "pt/pt.h"
}

#include "taint/taintengine.h"
#include "audit/audit.h"

#define print(str) std::cout << str << std::endl

#endif
