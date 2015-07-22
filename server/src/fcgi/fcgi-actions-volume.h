/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#ifndef FCGI_ACTIONS_VOLUME_H
#define FCGI_ACTIONS_VOLUME_H

#include "hashfs.h"

void fcgi_locate_volume(const sx_hashfs_volume_t *vol);
void fcgi_list_volume(const sx_hashfs_volume_t *vol);
void fcgi_create_volume(void);
void fcgi_acl_volume(void);
void fcgi_list_acl(const sx_hashfs_volume_t *vol);
void fcgi_volume_onoff(int enable);
void fcgi_delete_volume(void);
void fcgi_trigger_gc(void);
void fcgi_volsizes(void);
void fcgi_volume_mod(void);
void fcgi_node_status(void);
void fcgi_cluster_mode(void);
void fcgi_cluster_upgrade(void);
void fcgi_list_revision_blocks(const sx_hashfs_volume_t *vol);
void fcgi_mass_delete(void);
void fcgi_mass_rename(void);

#endif
