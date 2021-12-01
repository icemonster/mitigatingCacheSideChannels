/* CREDITS: https://gist.github.com/Thelouras58/a3b04a3df0d167743084ff94442f52d8 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include "gmp.h"

gmp_randstate_t stat;

void generatePrimes(mpz_t* p, mpz_t* q) {

    int primetest;
    long sd = 0;
    mpz_t seed;
    gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
    mpz_init(seed);
    srand((unsigned) getpid());
    sd = rand();
    mpz_set_ui(seed, sd);
    gmp_randseed(stat, seed);


    mpz_urandomb(*p, stat, 512);
    primetest = mpz_probab_prime_p(*p, 10);
    if (primetest != 0) {
        printf("p is prime\n");
    } else {
        //printf("p wasnt prime,choose next prime\n");
        mpz_nextprime(*p, *p);
    }

    mpz_urandomb(*q, stat, 512);
    primetest = mpz_probab_prime_p(*q, 10);
    if (primetest != 0) {
        // printf("q is prime\n");
    } else {
        // printf("p wasnt prime,choose next prime\n");
        mpz_nextprime(*q, *q);
    }


    printf("p and q generated!!\n");
    printf("p = ");
    mpz_out_str(stdout, 10, *p);
    printf("q = ");
    mpz_out_str(stdout, 10, *q);
    printf("\n------------------------------------------------------------------------------------------\n");
    mpz_clear(seed);
    return;
}

void computeNandF(mpz_t* q, mpz_t* p, mpz_t *phi, mpz_t* n) {
    
    mpz_t temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);
    //n=p*q
    mpz_mul(*n, *q, *p);
    mpz_sub_ui(temp1, *q, 1); //temp1=q-1
    mpz_sub_ui(temp2, *p, 1); //temp2=p-1
    //φ=(p-1)(q-1)
    mpz_mul(*phi, temp1, temp2);
    printf("N = ");
    mpz_out_str(stdout, 10, *n);
    printf("\n------------------------------------------------------------------------------------------\n");
}

void square(mpz_t *result, mpz_t mod){
    /* Square result modulo <mod> */
    mpz_mul(*result, *result, *result);
    mpz_mod(*result, *result, mod);
}

void multiply(mpz_t *result, mpz_t multiplier, mpz_t mod){
    /* Multiply result by <multiplier> modulo <mod> */
    mpz_mul(*result, *result, multiplier);
    mpz_mod(*result, *result, mod);
}

void sign(mpz_t* result, mpz_t* c, mpz_t* d, mpz_t* n) {
    char private_exp[1024]; /* Assumes 1024 bit keys */ 

    /* This is where we will try to leak the private exponent */
    //
    mpz_get_str(private_exp, 2, *d);
    printf("\nd = %s\n", private_exp);

    mpz_set_ui(*result, 1);

    /* Square and multiply */ 
    //mpz_powm(*m, *c, *d, *n); //Cheating with a mpz function
    for (unsigned int bit = 0; bit < strlen(private_exp); bit++){
        square(result, *n);
        if (private_exp[bit] == '1')
            multiply(result, *c, *n);
    }
}


int main() {
    /* Initialize big nums */
    mpz_t p, q, phi, e, n, d, c, dc;
    mpz_init(p);
    mpz_init(q);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(n);
    mpz_init(d);
    mpz_init(c);
    mpz_init(dc);
    
    //generatePrimes(&p, &q);
    /*Set a fixed public / private key */
    mpz_set_str(p, "6598168592865487695966055483152169576986188277223965989988605820450425234794292407188263226550931178288765139821996177355947586728902544389207390238620237", 10);
    mpz_set_str(q, "1283257433267004099742413378281324456385343425916054695784266246730843485996755548194537964225455055966036567941566094195224711222165391222221669935697993", 10);
    mpz_set_str(c, "2356165239786058617816931324189744545472175141604140933063805427348069", 10);
    mpz_set_ui(e, 65537);
    
    computeNandF(&q, &p, &phi, &n);
    mpz_invert(d, e, phi);
 
    printf("Signing ");
    mpz_out_str(stdout, 10, c);
    
    sign(&dc, &c, &d, &n);
    printf("------------------------------------------------------------------------------------------\n");
    printf("Signature: ");
    mpz_out_str(stdout, 10, dc);
    printf("\n");

    /* Clean memory */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(c);
    mpz_clear(d);
    mpz_clear(dc);
    return 0;
}
