

u32 tz_aes_testPart(u32 p1, u32 p2, u32 p3, u32 p4)
{
	return secure_call_with_param4(TZ_CALL_OPENSSL_AES_TEST_PART, p1,p2,p3,p4);
}


u32 tz_aes_init(u32 p1, u32 p2, u32 p3, u32 p4)
{
	return secure_call_with_param4(TZ_CALL_OPENSSL_AES_SETKEY, p1,p2,p3,p4);
}

u32 tz_aes_encrypt(u32 p1, u32 p2, u32 p3, u32 p4)
{
	return secure_call_with_param4(TZ_CALL_OPENSSL_AES_ENCRYPT, p1,p2,p3,p4);
}

u32 tz_aes_decrypt(u32 p1, u32 p2, u32 p3, u32 p4)
{
	return secure_call_with_param4(TZ_CALL_OPENSSL_AES_DECRYPT, p1,p2,p3,p4);
}

