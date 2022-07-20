#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main (int argc, char **argv) {
usleep(atoi(argv[1]));
return 0;
}
