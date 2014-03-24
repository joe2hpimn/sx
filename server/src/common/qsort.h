#ifndef __QSORT_H_
#define __QSORT_H_

#include "default.h"

typedef int sx_qsort_cmp_t(const void *thunk, const void *l, const void *r);
void sx_qsort(void *a, size_t n, size_t es, const void *thunk, sx_qsort_cmp_t *cmp);

#endif
