void runTest(int testNum, unsigned int testParameter)
{
	switch(testNum)
	{
		case 4503:
		{
			printk("v2 correctly guessed %u \n", attackIMX53v2(2000));
			break;
		}
		default:
			printk("error - running default test case in arm cache ut \n");
	}
}
