/*
------------------------------------------------------------------------------
rand.h: definitions for a random number generator
By Bob Jenkins, 1996, Public Domain
MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: renamed seed to flag
  980605: recommend RANDSIZL=4 for noncryptography.
  010626: note this is public domain
------------------------------------------------------------------------------
*/

#ifndef ISAAC
#define ISAAC

#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

/* context of random number generator */
struct isaac_ctx
{
    uint64_t randrsl[RANDSIZ];
    uint64_t randcnt;
    uint64_t mm[RANDSIZ];
    uint64_t aa, bb, cc;
};
typedef  struct isaac_ctx  isaac_ctx;

/*
------------------------------------------------------------------------------
 If (flag==TRUE), then use the contents of randrsl as the seed
------------------------------------------------------------------------------
*/
void isaac_init(isaac_ctx *ctx, int flag);

void isaac_seed(isaac_ctx *ctx, unsigned int seed);

void isaac(isaac_ctx *ctx);

uint64_t isaac_rand(isaac_ctx *ctx);

#endif

