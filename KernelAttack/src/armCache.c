#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/vmalloc.h>      /* need for vmalloc */
#include <linux/proc_fs.h>      
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <asm/system.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cache Side Channel Attack Module");
MODULE_AUTHOR("n1ng");

#define MAX_CMD_LEN
#define MAL_PROC_ENTRY "armCache"

static struct proc_dir_entry *proc_entry;

//these are the routiunes written for the exp
#include "aliSecureFunc.h"
#include "armUtil.h"

// static variables that are set via command line when the module is loaded
static char*  cmdBuff;
static char*  printBuff;

static int testToRun = 0; // defaulting to run the ArmCache test
//static int testParam = 0; // the test parameter


module_param(testToRun, int,  0644);
//module_param(testParam, int,  0644);

MODULE_PARM_DESC(testToRun, "Test Number to Run for the experiment kernel module");
//MODULE_PARM_DESC(testParam, "Parameter for the specific Test");


static u32 vir_addr;
static u32 phy_addr;
int * intPtr;

const u32 RUN_TEST_CMD = 1;
const u32 INVALID_CMD  = 0;

#include "TZAes.h"
#include "TZGhost.h"
#include "runTest.h"

int init_module(void)
{
   int ret = 0;

   printk(KERN_INFO "\n\n ********* Start Cache Kernel Module ********* \n\n");

   //allocate space for the command buffer
   cmdBuff 	 = kmalloc(1024, GFP_KERNEL);
   printBuff = kmalloc(2048, GFP_KERNEL);

   runTest(testToRun, 0);

   return ret;
}

void cleanup_module(void)
{
	
	
	if(vir_addr != 0)
		free_page(vir_addr);
		
    printk(KERN_INFO "\n\n ********* Ending Cache Module ********* \n\n");
}



