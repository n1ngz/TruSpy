// this header contains the utility function for cortex a8

#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/vmalloc.h>      /* need for vmalloc */
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>	// for tlb flsuh function
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/sched.h>
#include <asm/system.h>

#define ERROR_DEBUG  3
#define DEBUG_MSG    5

#define LockNoL2Way  0
#define Lock1L2Way   1
#define Lock2L2Way   2
#define Lock3L2Way   3
#define Lock4L2Way   4
#define Lock5L2Way   5
#define Lock6L2Way   6
#define Lock7L2Way   7
#define LockAllL2Way 8

static u32 penStorageVp = 0;
static const u32 penStorageSizeOrder = 8;
static u32 penAddress = 0x15000000;

static const u32 WRITE_ALLOC = 1;
static const u32 READ_ALLOC = 0;

const u32 PALA_DBG_ALL = 5;
const u32 PALA_DBG_INFO = 4;
const u32 PALA_DBG_WARN = 3;
const u32 PALA_DBG_ERROR = 1;


// there are a total of 256 kb L2 cache in the system
// and there are 8 ways, we will only be locking one in, and thus
// 1024 * 32 = 32768 bytes
static const u32 CortexA8L2WaySize = 0x8000;
static const u32 CortexA8CacheLineSize = 64; // 16 words, 4 byte a word


void flushL1L2(u8 level)
{

	// L1 32 kb, L2 256 kb
	// and also the geometry for
	// L1 is 4 way 128 set 64 byte per line a total of 32kb
	// L2 is 8 way 512 set 64 byte per line a total of 256kb

	//printing c9, L2 cache lock down register
	asm volatile(
			//clear the L1 first
			"MOV R2, #4							\n\t"
			"flush_loop_l1outer:				\n\t"
			"SUBS R2,#1							\n\t"
			"MOV R1, #128						\n\t"
				"flush_loop_l1inner:					\n\t"
				"SUBS R1,#1						\n\t"
				// now figure out the masking for level 0, that is
			    // way 31:30, set 12:6, level 3:1
				"MOV R3, R2, lsl #30			\n\t"
				"ADD R3, R3, R1, lsl #6			\n\t"
//				"MCR p15, 0, R3, c7, c6, 2  	\n\t"   // invalidate by set way
				"MCR p15, 0, R3, c7, c14, 2		\n\t"	// clean and invalidate by set way
//				"MCR p15, 0, R3, c7, c10, 2		\n\t"	// clean by set/way
				"cmp R1, #0						\n\t"
				"BNE flush_loop_l1inner				\n\t"
			"cmp R2, #0							\n\t"
			"BNE flush_loop_l1outer					\n\t"

			//decide to proceed to next level or not
			"MOV R1, #0							\n\t"
			"LDR R2, %0							\n\t"
			"CMP R1, R2							\n\t"
			"BEQ flush_endCacheFlush					\n\t"


			"MOV R2, #8							\n\t"
			"flush_loop_l2outer:						\n\t"
			"SUBS R2,#1							\n\t"
			"MOV R1, #512					\n\t"
				"flush_loop_l2inner:					\n\t"
				"SUBS R1,#1						\n\t"
				// now figure out the masking for level 2, that is
			    // way 31:29, set 14:6, level 3:1
				"MOV  R3, #2					\n\t"
				"ADD  R3, R3, R2, lsl #29		\n\t"
				"ADD  R3, R3, R1, lsl #6		\n\t"
//				"MCR p15, 0, R3, c7, c6, 2  	\n\t"   // invalidate by set way
				"MCR p15, 0, R3, c7, c14, 2		\n\t"	// clean and invalidate by set way
//				"MCR p15, 0, R3, c7, c10, 2		\n\t"	// clean by set/way
				"cmp R1, #0						\n\t"
				"BNE flush_loop_l2inner				\n\t"
			"cmp R2, #0							\n\t"
			"BNE flush_loop_l2outer					\n\t"
			"flush_endCacheFlush:						\n\t"
			"	DSB								\n\t"
			"	ISB								\n\t"
			:  				// output
			:  "m"(level)	// input
			: "r1","r2","r3","r4"
	);

}


void enableUserAccessToPerformanceCounter()
{
  /* enable user-mode access to the performance counter*/
  asm ("MCR p15, 0, %0, C9, C14, 0\n\t" :: "r"(1));

  /* disable counter overflow interrupts (just in case)*/
  asm ("MCR p15, 0, %0, C9, C14, 2\n\t" :: "r"(0x8000000f));
}