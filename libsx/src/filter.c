/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "default.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "libsx-int.h"
#include "misc.h"
#include "ltdl.h"
#include "filter.h"

struct _sxc_filter {
    sxc_client_t *sx;
};

static const char *filter_gettname(sxf_type_t type)
{
	int i;

    for(i = 0; sxi_filter_tname[i].tname; i++)
	if(sxi_filter_tname[i].type == type)
	    return sxi_filter_tname[i].tname;

    return "unknown";
}

static int filter_register(sxc_client_t *sx, const char *filename)
{
	lt_dlhandle dlh;
	sxc_filter_t *filter;
	struct filter_ctx *fctx;
	struct filter_handle *ph = NULL;
	int i, ret = 0;

    if(strstr(filename, "libsxf_")) {
	dlh = lt_dlopen(filename);
	if(dlh) {
	    if(!(filter = (sxc_filter_t *) lt_dlsym(dlh, "sxc_filter"))) {
		SXDEBUG("Invalid filter %s: %s", filename, lt_dlerror());
		return 1;
	    }
	    if(filter->abi_version != SXF_ABI_VERSION) {
		SXDEBUG("ABI version mismatch (filter: %d, library: %d) with %s\n", filter->abi_version, SXF_ABI_VERSION, filename);
		lt_dlclose(dlh);
		return 1;
	    }
	    if(!filter->shortname || !filter->shortdesc || !filter->summary || !filter->uuid) {
		SXDEBUG("Invalid filter %s (name/summary/uuid fields missing)", filename);
		lt_dlclose(dlh);
		return 1;
	    }
	    SXDEBUG("Loading filter \"%s\", version %d.%d, type %d, uuid %s (%s)", filter->shortname, filter->version[0], filter->version[1], filter->type, filter->uuid, filename);
	    fctx = sxi_get_fctx(sx);
	    for(i = 0; i < fctx->filter_cnt; i++) {
		if(!strcmp(fctx->filters[i].f->uuid, filter->uuid)) {
		    if(fctx->filters[i].f->version[0] >= filter->version[0] && fctx->filters[i].f->version[1] >= filter->version[1]) {
			SXDEBUG("Skipping duplicate/older version of filter \"%s\"", filter->shortname);
			lt_dlclose(dlh);
			return 2;
		    }
		    SXDEBUG("Replacing older version (%d.%d) of filter \"%s\"", fctx->filters[i].f->version[0], fctx->filters[i].f->version[1], fctx->filters[i].f->shortname);
		    ph = &fctx->filters[i];
		    if(ph->active && ph->f->shutdown)
			ph->f->shutdown(ph, ph->ctx);
		    lt_dlclose(ph->dlh);
		    ph->active = 0;
		    ret = 2;
		}
	    }

	    if(!ph) {
		fctx->filter_cnt++;
		fctx->filters = sxi_realloc(sx, fctx->filters, fctx->filter_cnt * sizeof(struct filter_handle));

		if(!fctx->filters) {
		    fctx->filter_cnt = 0;
		    lt_dlclose(dlh);
		    return 1;
		}
		ph = &fctx->filters[fctx->filter_cnt - 1];
	    }
	    ph->dlh = dlh;
	    ph->ctx = NULL;
	    ph->active = 0;
	    ph->cfg = NULL;
            ph->sx = sx;
	    filter->tname = filter_gettname(filter->type);
	    if(sxi_uuid_parse(filter->uuid, ph->uuid_bin) == -1) {
		SXDEBUG("Invalid UUID for filter \"%s\"", filter->shortname);
		fctx->filter_cnt--;
		lt_dlclose(dlh);
		return 1;
	    }
	    ph->f = filter;
	    if(ph->f->init && ph->f->init(ph, &ph->ctx) < 0) {
		SXDEBUG("Can't initialize filter \"%s\"", filter->shortname);
		fctx->filter_cnt--;
		lt_dlclose(dlh);
		return 1;
	    }
	    ph->active = 1;
	} else {
	    SXDEBUG("Error while registering filter %s: %s", filename, lt_dlerror());
	    return 1;
	}
    }
    return ret;
}

struct filter_handle *sxi_filter_gethandle(sxc_client_t *sx, const uint8_t *uuid)
{
    struct filter_ctx *fctx;
    int i;

    fctx = sxi_get_fctx(sx);
    if(!fctx || fctx->filter_cnt <= 0) {
	SXDEBUG("No filters available");
	sxi_seterr(sx, SXE_EFILTER, "No filters available");
	return NULL;
    }

    for(i = 0; i < fctx->filter_cnt; i++)
	if(!memcmp(fctx->filters[i].uuid_bin, uuid, 16))
	    return &fctx->filters[i];

    return NULL;
}

static int filter_loadall(sxc_client_t *sx, const char *filter_dir)
{
    struct filter_ctx *fctx;
    DIR *dir;
    struct dirent *dent;
    struct stat sb;
    char *path;
    int ret = 0, pcnt = 0;

    if(!sx || !filter_dir)
	return 1;
    fctx = sxi_get_fctx(sx);

    if(fctx->filter_cnt == -1) {
	SXDEBUG("Filter subsystem not available");
	sxi_seterr(sx, SXE_EFILTER, "Filter subsystem not available");
	return 1;
    }

    if(!(dir = opendir(filter_dir))) {
	SXDEBUG("Can't open filter directory %s\n", filter_dir);
	sxi_seterr(sx, SXE_EFILTER, "Can't open filter directory %s\n", filter_dir);
	return 1;
    }

    while((dent = readdir(dir))) {
	if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		unsigned int pathlen = strlen(filter_dir) + strlen(dent->d_name) + 2;
	    path = malloc(pathlen);
	    if(!path) {
		SXDEBUG("OOM allocating path");
		sxi_setsyserr(sx, SXE_EMEM, "OOM allocating path");
		closedir(dir);
		return 1;
	    }
	    snprintf(path, pathlen, "%s/%s", filter_dir, dent->d_name); /* FIXME: path separator */
	    if(lstat(path, &sb) == -1) {
		free(path);
		continue;
	    }

	    if(S_ISDIR(sb.st_mode)) {
		ret = filter_loadall(sx, path);
	    } else if(S_ISREG(sb.st_mode) && !strncmp(dent->d_name, "libsxf_", 7) && strstr(dent->d_name, ".so")) {
		ret = filter_register(sx, path);
		if(!ret)
		    pcnt++;
		else if(ret == 2)
		    ret = 0;
	    }
	    free(path);
	}
    }
    closedir(dir);

    if(!pcnt && ret)
	return ret;

    /*
    if(pcnt)
	SXDEBUG("Loaded %d filter(s) from %s", pcnt, filter_dir);
    */

    return 0;
}

int sxc_filter_loadall(sxc_client_t *sx, const char *filter_dir)
{
	int ret;
	struct filter_ctx *fctx;

    SXDEBUG("Searching for filters in %s", filter_dir);
    ret = filter_loadall(sx, filter_dir);
    fctx = sxi_get_fctx(sx);
    if(!ret && fctx->filter_cnt >= 1)
	SXDEBUG("Loaded %d filter(s) from %s", fctx->filter_cnt, filter_dir);
    return ret;
}

static const struct filter_cfg *filter_get_cfg(struct filter_handle *fh, const char *volname)
{
    const struct filter_cfg *cfg;
    if(!fh || !volname)
	return NULL;

    cfg = fh->cfg;
    while(cfg) {
	if(!strcmp(cfg->volname, volname))
	    return cfg;
	cfg = cfg->next;
    }
    return NULL;
}

const void *sxi_filter_get_cfg(struct filter_handle *fh, const char *volname)
{
    const struct filter_cfg *cfg = filter_get_cfg(fh, volname);
    return cfg ? cfg->cfg : NULL;
}

unsigned int sxi_filter_get_cfg_len(struct filter_handle *fh, const char *volname)
{
    const struct filter_cfg *cfg = filter_get_cfg(fh, volname);
    return cfg ? cfg->cfg_len : 0;
}

int sxi_filter_add_cfg(struct filter_handle *fh, const char *volname, const void *cfg, unsigned int cfg_len)
{
    struct filter_cfg *newcfg;
    if(!fh || !volname || !cfg || !cfg_len)
	return -1;

    if(filter_get_cfg(fh, volname))
	return 0;

    newcfg = malloc(sizeof(struct filter_cfg));
    if(!newcfg) {
	sxi_seterr(fh->sx, SXE_EMEM, "OOM");
	return -1;
    }
    newcfg->volname = strdup(volname);
    if(!newcfg->volname) {
	free(newcfg);
	sxi_seterr(fh->sx, SXE_EMEM, "OOM");
	return -1;
    }
    newcfg->cfg = malloc(cfg_len);
    if(!newcfg->cfg) {
	free(newcfg->volname);
	free(newcfg);
	sxi_seterr(fh->sx, SXE_EMEM, "OOM");
	return -1;
    }
    memcpy(newcfg->cfg, cfg, cfg_len);
    newcfg->cfg_len = cfg_len;
    newcfg->next = fh->cfg;
    fh->cfg = newcfg;
    return 0;
}

void sxi_filter_unloadall(sxc_client_t *sx)
{
    struct filter_ctx *fctx;
    int i;
    struct filter_handle *ph;
    struct filter_cfg *c;

    if(!sx)
	return;
    fctx = sxi_get_fctx(sx);

    if(fctx->filter_cnt < 1)
	return;

    SXDEBUG("Shutting down %d filter(s)", fctx->filter_cnt);
    for(i = 0; i < fctx->filter_cnt; i++) {
	ph = &fctx->filters[i];
	if(ph->active && ph->f->shutdown)
	    ph->f->shutdown(ph, ph->ctx);
	while(ph->cfg) {
	    c = ph->cfg;
	    free(c->volname);
	    free(c->cfg);
	    ph->cfg = ph->cfg->next;
	    free(c);
	}
	lt_dlclose((lt_dlhandle) ph->dlh);
    }
    free(fctx->filters);
}
