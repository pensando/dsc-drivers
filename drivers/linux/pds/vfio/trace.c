#define CREATE_TRACE_POINTS

#include "trace.h"

#undef TRACE_SYSTEM
#define CREATE_TRACE_POINTS

#include "trace.h"

const char *
dirty_xor_dma_addrs(struct trace_seq *p,
		    u64 region_start,
		    u16 page_size,
		    u64 bmp_offset_bit,
		    u64 dword,
		    u64 xor_bits)
{
	const char *ret = trace_seq_buffer_ptr(p);
	u64 bit_i;

	for (bit_i = 0; bit_i < BITS_PER_U64; ++bit_i) {
		if (xor_bits & BIT(bit_i)) {
			u64 abs_bit_i = bmp_offset_bit + dword * 64 + bit_i;
			u64 bit_dma_addr = abs_bit_i * page_size + region_start;

			trace_seq_printf(p, "%#llx\n", bit_dma_addr);
		}
	}

	trace_seq_putc(p, 0);
	return ret;
}
