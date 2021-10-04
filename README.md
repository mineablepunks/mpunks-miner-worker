i use sh make3.sh to make it
there's no parse args for command line yet, it's all edit and recompile for inputs.

```
static const char *LASTMINED = "422000000003B0019000000";
static const char *ADDRESS = "E8946EC499a839c72E60bA7d437E28cd73a3f487"; 
```
are address

```
__device__ const uint64_t device_difficulty_upper = 0;
__device__ const uint64_t device_difficulty_lower = 5731203885580;
```

 is difficulty level
just run it `./mminer3 > out.log &`
line 623 is where inputs are added to digest.
```
    /* set msg */
    printMsg("pre msg", msg, 32);
    size_t count;
    mpz_export(msg, &count, 1, 12, 1, 0, lastMinedPunkAsset_mpz);
    mpz_export(msg + 12, &count, 1, 9, 1, 0, sender_mpz);
    printMsg("pos msg", msg, 32);
```
