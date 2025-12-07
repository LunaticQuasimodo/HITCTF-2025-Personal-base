#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {

    setuid(0);

    system("cat /home/ctf/flag");

    return 0;
}