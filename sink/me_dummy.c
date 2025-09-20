#include <nfp.h>

__export __mem40 unsigned int dummy_counter = 0;

void main(void) {
    while (1) {
        dummy_counter++;
    }
}
