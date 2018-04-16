#include "TzFuncNum.h"

#define TZ_CALL_DUMPCFG 						41
#define TZ_CALL_ENABLE_S_CACHING				44
#define TZ_CALL_OPENSSL_AES_TEST 				163
#define TZ_CALL_OPENSSL_AES_SETKEY 				164
#define TZ_CALL_OPENSSL_AES_ENCRYPT 			165
#define TZ_CALL_OPENSSL_AES_DECRYPT 			166
#define TZ_CALL_OPENSSL_AES_ENCRYPT_WITH_KEY 	167
#define TZ_CALL_OPENSSL_AES_DECRYPT_WITH_KEY 	168
#define TZ_CALL_OPENSSL_AES_TEST_PART			169
#define TZ_CALL_TEST_OPENSSL_AES_ENCRYPT		170
#define TZ_CALL_VERIFY_CACHING					171



unsigned int secure_call_with_param(int callNum, u32 param)
{
	printk("");
	unsigned long readdata;
	asm volatile("mov r0, %0 \n\t"
				 "mov r1, %1 \n\t"
				:
				:"r"(callNum),"r"(param)
				:"r0","r1","r2","r3","r4","r5","r6"
				);

	asm volatile("smc 0x0\n\t");

	asm volatile("mov %0,r0\n\t"
				:"=r"(readdata)
				:
				: "r0","r1","r2","r3"
				);

//	printk("readdata:%lx\n",readdata);

	return readdata;
}

unsigned int secure_call_with_param2(int callNum, u32 param, u32 param2)
{
	printk("");
	unsigned long readdata;
	asm volatile("mov r0, %0 \n\t"
				 "mov r1, %1 \n\t"
				 "mov r2, %2 \n\t"
				:
				:"r"(callNum),"r"(param),"r"(param2)
				:"r0","r1","r2","r3"
				);

	asm volatile("smc 0x0\n\t");

	asm volatile("mov %0,r0\n\t"
				:"=r"(readdata)
				:
				: "r0","r1","r2","r3","r4"
				);

//	printk("readdata:%lx\n",readdata);

	return readdata;
}


unsigned int secure_call_with_param3(int callNum, u32 param, u32 param2, u32 param3)
{
	printk("");
	unsigned long readdata;
	asm volatile("mov r0, %0 \n\t"
				 "mov r1, %1 \n\t"
				 "mov r2, %2 \n\t"
				 "mov r3, %3 \n\t"
				:
				:"r"(callNum),"r"(param),"r"(param2),"r"(param3)
				:"r0","r1","r2","r3"
				);

	asm volatile("smc 0x0\n\t");

	asm volatile("mov %0,r0\n\t"
				:"=r"(readdata)
				:
				: "r0","r1","r2","r3","r4"
				);

	return readdata;
}

unsigned int secure_call_with_param4(int callNum, u32 param, u32 param2, u32 param3, u32 param4)
{
	printk("");
	unsigned long readdata;
	asm volatile("mov r0, %0 \n\t"
				 "mov r1, %1 \n\t"
				 "mov r2, %2 \n\t"
				 "mov r3, %3 \n\t"
				 "mov r4, %4 \n\t" 
				:
				:"r"(callNum),"r"(param),"r"(param2),"r"(param3),"r"(param4)
				:"r0","r1","r2","r3"
				);

	asm volatile("smc 0x0\n\t");

	asm volatile("mov %0,r0\n\t"
				:"=r"(readdata)
				:
				: "r0","r1","r2","r3","r4"
				);

//	printk("readdata:%lx\n",readdata);

	return readdata;
}




