#define TRACE_SYSTEM pds_vfio

#if !defined(_PDS_VFIO_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _PDS_VFIO_TRACE_H_

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#define BITS_PER_U64	(BITS_PER_BYTE * sizeof(u64))

const char *
dirty_xor_dma_addrs(struct trace_seq *p,
		    u64 region_start,
		    u16 page_size,
		    u64 bmp_offset_bit,
		    u64 dword,
		    u64 xor_bits);

#define __dirty_xor_dma_addrs(region_start, page_size, bmp_offset_bit, dword, xor_bits) \
	dirty_xor_dma_addrs(p, region_start, page_size, bmp_offset_bit, dword, xor_bits)

TRACE_EVENT(xor_bits,
	TP_PROTO(struct device *dev,
	         u32 bmp_offset_bit,
	         int dword,
	         u64 xor_bits
	),

	TP_ARGS(dev, bmp_offset_bit, dword, xor_bits),

	TP_STRUCT__entry(__string(dev_name, dev_name(dev))
			 __field(u32, bmp_offset_bit)
			 __field(int, dword)
			 __field(u64, xor_bits)
			 __field(u8, count)
	),

	TP_fast_assign(__assign_str(dev_name, dev_name(dev));
		       __entry->bmp_offset_bit = bmp_offset_bit;
		       __entry->dword = dword;
		       __entry->xor_bits = xor_bits;
		       __entry->count = hweight64(xor_bits);
	),

	TP_printk("%s: bit offset %lu: xor %#llx count %u",
	          __get_str(dev_name),
	          __entry->bmp_offset_bit + __entry->dword * BITS_PER_U64,
	          __entry->xor_bits, __entry->count
	)
);

TRACE_EVENT(xor_addresses,
	TP_PROTO(struct device *dev,
		 u64 region_start,
		 u16 page_size,
		 u32 bmp_offset_bit,
		 int dword,
		 u64 xor_bits
	),

	TP_ARGS(dev, region_start, page_size, bmp_offset_bit, dword, xor_bits),

	TP_STRUCT__entry(__string(dev_name, dev_name(dev))
			 __field(u64, region_start)
			 __field(u16, page_size)
			 __field(u32, bmp_offset_bit)
			 __field(int, dword)
			 __field(u64, xor_bits)
			 __field(u8, count)
	),

	TP_fast_assign(__assign_str(dev_name, dev_name(dev));
		       __entry->region_start = region_start;
		       __entry->page_size = page_size;
		       __entry->bmp_offset_bit = bmp_offset_bit;
		       __entry->dword = dword;
		       __entry->xor_bits = xor_bits;
		       __entry->count = hweight64(xor_bits);
	),

	TP_printk("%s: bit offset %lu: xor %#llx count %u\ndirty dma_addrs:\n%s",
		  __get_str(dev_name),
		  __entry->bmp_offset_bit + __entry->dword * BITS_PER_U64,
		  __entry->xor_bits, __entry->count,
		  __dirty_xor_dma_addrs(__entry->region_start,
					__entry->page_size,
					__entry->bmp_offset_bit,
					__entry->dword,
					__entry->xor_bits)
	)
);

TRACE_EVENT(xor_total_dirty_count,
	TP_PROTO(struct device *dev,
	         u64 *dirty_bitmap,
	         int dword_count
	),

	TP_ARGS(dev, dirty_bitmap, dword_count),

	TP_STRUCT__entry(__string(dev_name, dev_name(dev))
			 __field(u64, total_count)
	),

	TP_fast_assign(
		int i;

		__assign_str(dev_name, dev_name(dev));
		__entry->total_count = 0;

		for (i = 0; i < dword_count; ++i)
			__entry->total_count += hweight64(dirty_bitmap[i]);
	),

	TP_printk("%s: total dirty count: %llu",
	          __get_str(dev_name), __entry->total_count
	)
);

TRACE_EVENT(lm_action_time,
	TP_PROTO(struct device *dev,
		 const char *lm_action,
		 unsigned long jiffies_delta
	),

	TP_ARGS(dev, lm_action, jiffies_delta),

	TP_STRUCT__entry(__string(dev_name, dev_name(dev))
			 __string(lm_action_name, lm_action)
			 __field(unsigned int, elapsed_ms)
	),

	TP_fast_assign(
		__assign_str(dev_name, dev_name(dev));
		__assign_str(lm_action_name, lm_action);
		__entry->elapsed_ms = jiffies_delta_to_msecs(jiffies_delta);
	),

	TP_printk("%s: lm_action=%s elapsed_ms=%u",
		  __get_str(dev_name), __get_str(lm_action_name), __entry->elapsed_ms
	)
);

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
#endif /* _TRACE_H_ */
