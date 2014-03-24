/*
 * Copyright (c) 2007-2011, Lloyd Hilaiel <lloyd@hilaiel.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <yajl/yajl_parse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int null(void *ctx) {
    printf("Got NULL\n");
    return 1;
}

static int boolean(void *ctx, int boolean) {
    printf("Got BOOL\n");
    return 1;
}

static int number(void *ctx, const char *s, size_t l) {
    char *d = malloc(l+1);
    memcpy(d, s, l);
    d[l] = '\0';
    printf("Got NUMBER: %s\n", d);
    free(d);
    return 1;
}

static int string(void * ctx, const char *s, size_t l) {
    char *d = malloc(l+1);
    memcpy(d, s, l);
    d[l] = '\0';
    printf("Got STRING: %s\n", d);
    free(d);
    return 1;
}

static int map_key(void *ctx, const char *s, size_t l) {
    char *d = malloc(l+1);
    memcpy(d, s, l);
    d[l] = '\0';
    printf("Got MAP KEY: %s\n", d);
    free(d);
    return 1;
}

static int start_map(void *ctx) {
    printf("Got MAP START\n");
    return 1;
}

static int end_map(void *ctx) {
    printf("Got MAP END\n");
    return 1;
}

static int start_array(void *ctx) {
    printf("Got ARRAY START\n");
    return 1;
}

static int end_array(void *ctx) {
    printf("Got ARRAY END\n");
    return 1;
}

static yajl_callbacks callbacks = {
    null,
    boolean,
    NULL,
    NULL,
    number,
    string,
    start_map,
    map_key,
    end_map,
    start_array,
    end_array
};

int main(int argc, char ** argv) {
    char buf[1024];
    yajl_handle hand = yajl_alloc(&callbacks, NULL, NULL);

    while(!feof(stdin)) {
	int readsz = fread(buf, 1, sizeof(buf), stdin);
        if(yajl_parse(hand, buf, readsz) != yajl_status_ok) {
	    printf("parsing failed 1\n");
	    return 1;
	}
    }
    if(yajl_complete_parse(hand) != yajl_status_ok) {
	printf("parsing failed 2\n");
	return 1;
    }
    return 0;
}


