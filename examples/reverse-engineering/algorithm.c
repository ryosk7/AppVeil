// Synthetic, intentionally public benchmark. Not proprietary code.
#include <stdint.h>
uint32_t polynomial_score(uint32_t x) { return ((x * 17u + 31u) ^ (x >> 3)); }
