/*
------------------------------------------------------------------------------
rand.c: By Bob Jenkins.  My random number generator, ISAAC.  Public Domain.
MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: added main (ifdef'ed out), also rearranged randinit()
  010626: Note that this is public domain
------------------------------------------------------------------------------
*/
#include "default.h"
#include "isaac.h"

#include <stdio.h>
#include <string.h>

#define ind(mm,x)  (*(uint64_t *)((uint8_t *)(mm) + ((x) & ((RANDSIZ-1)<<3))))
#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
  x = *m;  \
  a = (mix) + *(m2++); \
  *(m++) = y = ind(mm,x) + a + b; \
  *(r++) = b = ind(mm,y>>RANDSIZL) + x; \
}

void isaac(isaac_ctx *ctx)
{
  register uint64_t a,b,x,y,*m,*m2,*r,*mend;
  r=ctx->randrsl;
  ctx->cc++;
  a = ctx->aa; b = ctx->bb + ctx->cc;
  for (m = ctx->mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
  {
    rngstep(~(a^(a<<21)), a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a>>5)  , a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a<<12) , a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a>>33) , a, b, ctx->mm, m, m2, r, x);
  }
  for (m2 = ctx->mm; m2<mend; )
  {
    rngstep(~(a^(a<<21)), a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a>>5)  , a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a<<12) , a, b, ctx->mm, m, m2, r, x);
    rngstep(  a^(a>>33) , a, b, ctx->mm, m, m2, r, x);
  }
  ctx->bb = b; ctx->aa = a;
  ctx->randcnt=0;
}

#define mix(a,b,c,d,e,f,g,h) \
{ \
   a-=e; f^=h>>9;  h+=a; \
   b-=f; g^=a<<9;  a+=b; \
   c-=g; h^=b>>23; b+=c; \
   d-=h; a^=c<<15; c+=d; \
   e-=a; b^=d>>14; d+=e; \
   f-=b; c^=e<<20; e+=f; \
   g-=c; d^=f>>17; f+=g; \
   h-=d; e^=g<<14; g+=h; \
}

void isaac_init(isaac_ctx *ctx, int flag)
{
   int i;
   uint64_t a,b,c,d,e,f,g,h;
   ctx->aa=ctx->bb=ctx->cc=(uint64_t)0;
   a=b=c=d=e=f=g=h=0x9e3779b97f4a7c13LL;  /* the golden ratio */

   for (i=0; i<4; ++i)                    /* scramble it */
   {
     mix(a,b,c,d,e,f,g,h);
   }

   for (i=0; i<RANDSIZ; i+=8)   /* fill in mm[] with messy stuff */
   {
     if (flag)                  /* use all the information in the seed */
     {
       a+=ctx->randrsl[i  ]; b+=ctx->randrsl[i+1]; c+=ctx->randrsl[i+2]; d+=ctx->randrsl[i+3];
       e+=ctx->randrsl[i+4]; f+=ctx->randrsl[i+5]; g+=ctx->randrsl[i+6]; h+=ctx->randrsl[i+7];
     }
     mix(a,b,c,d,e,f,g,h);
     ctx->mm[i  ]=a; ctx->mm[i+1]=b; ctx->mm[i+2]=c; ctx->mm[i+3]=d;
     ctx->mm[i+4]=e; ctx->mm[i+5]=f; ctx->mm[i+6]=g; ctx->mm[i+7]=h;
   }

   if (flag) 
   {        /* do a second pass to make all of the seed affect all of mm */
     for (i=0; i<RANDSIZ; i+=8)
     {
       a+=ctx->mm[i  ]; b+=ctx->mm[i+1]; c+=ctx->mm[i+2]; d+=ctx->mm[i+3];
       e+=ctx->mm[i+4]; f+=ctx->mm[i+5]; g+=ctx->mm[i+6]; h+=ctx->mm[i+7];
       mix(a,b,c,d,e,f,g,h);
       ctx->mm[i  ]=a; ctx->mm[i+1]=b; ctx->mm[i+2]=c; ctx->mm[i+3]=d;
       ctx->mm[i+4]=e; ctx->mm[i+5]=f; ctx->mm[i+6]=g; ctx->mm[i+7]=h;
     }
   }

   isaac(ctx);          /* fill in the first set of results */
}

typedef struct { uint32_t a; uint32_t b; uint32_t c; uint32_t d; } initctx;
#define ROT(a,b) (((a)<<(b))|((a)>>(32-(b))))
static uint32_t initval(initctx *x) {
    uint32_t e = x->a - ROT(x->b, 5);
    x->a = x->b ^ ROT(x->c, 7);
    x->b = x->c + x->d;
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}

void isaac_seed(isaac_ctx *ctx, unsigned int seed)
{
	unsigned int i;
	initctx ictx;

    ictx.a = 0xa712e1d5;
    ictx.b = ictx.c = ictx.d = seed;
    for(i = 0; i < RANDSIZ; i++)
	ctx->randrsl[i] = initval(&ictx);
    isaac_init(ctx, 1);
    for(i = 0; i < seed % 1024; i++)
	isaac(ctx);
}

uint64_t isaac_rand(isaac_ctx *ctx)
{
    if(ctx->randcnt == RANDSIZ)
	isaac(ctx);
    return ctx->randrsl[ctx->randcnt++];
}
