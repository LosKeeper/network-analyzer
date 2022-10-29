#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void print_verbosity(u_char desired_level, u_char msg_level, const char *msg,
                     ...);