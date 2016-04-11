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

#include "default.h"
#include <string.h>
#include "fcgi-utils.h"
#include "fcgi-actions.h"
#include "fcgi-actions-cluster.h"
#include "fcgi-actions-volume.h"
#include "fcgi-actions-node.h"
#include "fcgi-actions-block.h"
#include "fcgi-actions-file.h"
#include "fcgi-actions-user.h"
#include "fcgi-actions-job.h"
#include "hashfs.h"
#include "sx.h"

void cluster_ops(void) {
    if(verb != VERB_HEAD && verb != VERB_GET) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS\r\n");
	quit_errmsg(405, "Method Not Allowed");
    }

    /* Cluster queries - require either a valid user or ADMIN 
     * priv enforcement in fcgi_handle_cluster_requests() */
    quit_unless_authed();
    fcgi_handle_cluster_requests();
}

void volume_ops(void) {
    rc_ty s;
    quit_unless_authed();

    if(verb != VERB_HEAD && verb != VERB_GET && verb != VERB_PUT && verb != VERB_DELETE) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\n");
	quit_errmsg(405, "Method Not Allowed");
    }

    if(verb == VERB_HEAD || verb == VERB_GET) {
	const sx_hashfs_volume_t *vol;

	if(!strcmp(volume, ".replblk")) {
	    /* Bulk block and blockmeta xfer (s2s, replacement node repopulation) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_send_replacement_blocks();
	    return;
	}

        if(!strcmp(volume, ".volrepblk")) {
            /* Bulk block and blockmeta xfer (s2s, volume replica repopulation) - CLUSTER required */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_send_volrep_blocks();
            return;
        }

	if(!strcmp(volume, ".users")) {
	    /* List users - ADMIN required */
	    quit_unless_has(PRIV_ADMIN);
	    fcgi_list_users();
	    return;
	}

        if(!strcmp(volume, ".status")) { /* Get node status */
            quit_unless_has(PRIV_ADMIN);
            fcgi_node_status();
            return;
        }

        /* Get basic user information */
        if(!strcmp(volume, ".self")) {
            fcgi_self();
            return;
        }

        if(!strcmp(volume, ".clusterSettings")) {
            quit_unless_has(PRIV_ADMIN);
            /* Set cluster settings - ADMIN required */
            fcgi_get_cluster_settings();
            return;
        }

	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");

	s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
	switch(s) {
	case OK:
	    break;
	case ENOENT:
	    quit_errmsg(404, "No such volume");
	case EINVAL:
	    quit_errnum(400);
	default:
	    quit_errnum(500);
	}

	/* Locating or listing volume data requires READ|WRITE|ACL access or better */
        if (!has_priv(PRIV_READ) && !has_priv(PRIV_WRITE) && !has_priv(PRIV_MANAGER) && !has_priv(PRIV_ADMIN))
            quit_errmsg(403, "Permission denied: not enough privileges");

	if(has_arg("o")) {
	    if(arg_is("o", "locate")) {
		/* Locate volume, i.e. find the nodes that manage it - READ required */
		fcgi_locate_volume(vol);
		return;
	    } else if(arg_is("o", "acl")) {
		/* List privs - every user can list its own privileges, admin
                 * can list everything. You need to have some privileges though */
		fcgi_list_acl(vol);
		return;
	    }
	}

        quit_unless_has(PRIV_READ);

	if(!has_arg("o") || arg_is("o", "list")) {
	    /* List volume content - READ required */
	    fcgi_list_volume(vol);
        } else if(arg_is("o","revision_blocks")) {
            quit_unless_has(PRIV_CLUSTER);
            fcgi_list_revision_blocks(vol);
	} else
	    quit_errnum(404);

	return;
    }

    if (verb == VERB_PUT && arg_is("o","acl")) {
	/* Update volume privs - ADMIN or OWNER required */
	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");
	if(!has_priv(PRIV_ADMIN))
	    quit_unless_has(PRIV_MANAGER);
	fcgi_acl_volume();
	return;
    }

    if(verb == VERB_DELETE && has_arg("filter")) {
        if(is_reserved())
            quit_errmsg(403, "Volume name is reserved");
        /* Delete files matching given filter */
        quit_unless_has(PRIV_WRITE);
        fcgi_mass_delete();
        return;
    }

    /* privs enforcement will be done after body parsing */
    if(verb == VERB_PUT && arg_is("o", "mod")) {
        if(is_reserved())
            quit_errmsg(403, "Volume name is reserved");
        /* Modify volume */
        fcgi_volume_mod();
        return;
    }

    /* Volume replica modification queries */
    if(verb == VERB_PUT && arg_is("o", "replica")) {
        if(is_reserved())
            quit_errmsg(403, "Volume name is reserved");
        quit_unless_has(PRIV_ADMIN);

        /* Modify volume replica (user request, ADMIN required */
        fcgi_modify_volume_replica();
        return;
    }

    if(verb == VERB_PUT && has_arg("source") && has_arg("dest")) {
        if(is_reserved())
            quit_errmsg(403, "Volume name is reserved");
	if(content_len())
	    quit_errmsg(400, "Invalid request");
        /* Rename files matching given filter to the destination pattern */
        quit_unless_has(PRIV_WRITE);
        fcgi_mass_rename();
        return;
    }

    /* Only ADMIN or better allowed beyond this point */
    quit_unless_has(PRIV_ADMIN);

    if(verb == VERB_PUT && (arg_is("o","disable") || arg_is("o","enable"))) {
	/* Enable / disable volume (2pc/s2s) - CLUSTER required */
	quit_unless_has(PRIV_CLUSTER);
	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");
	if(content_len())
	    quit_errmsg(400, "Invalid request");
	fcgi_volume_onoff(arg_is("o","enable"));
	return;
    }

    if(verb == VERB_PUT) {
	if(!strcmp(".node", volume)) {
	    /* Initialize bare node into a cluster (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_node_init();
	} else if(!strcmp(".dist", volume)) {
	    /* Create/enable new distribution (s2s entry) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    if(content_len())
		fcgi_new_distribution();
	    else
		fcgi_enable_distribution();
	} else if(!strcmp(".rebalance", volume) && !content_len()) {
	    /* Initiate rebalance process (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    if(content_len())
		quit_errmsg(400, "Invalid request");
	    fcgi_start_rebalance();
	} else if(!strcmp(volume, ".sync")) {
	    /* Syncronize global objects (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
            fcgi_sync_globs();
        } else if (!strcmp(volume, ".gc")) {
	    quit_unless_has(PRIV_ADMIN);
	    if(content_len())
		quit_errmsg(400, "Invalid request");
            fcgi_trigger_gc();
        } else if(!strcmp(".distlock", volume)) {
            /* Set sxadm operation lock - ADMIN required */
            fcgi_distlock();
	} else if(!strcmp(".nodes", volume)) {
	    /* Update distribution (sxadm entry) - ADMIN required */
	    if(has_arg("setfaulty"))
		fcgi_mark_faultynodes();
	    else
		fcgi_set_nodes();
	} else if (!strcmp(".users", volume)) {
	    /* Create new user - ADMIN required */
	    fcgi_create_user();
        } else if (!strcmp(volume, ".data")) {
            quit_unless_has(PRIV_CLUSTER);
            fcgi_hashop_inuse();
	} else if(!strcmp(volume, ".volsizes")) {
            quit_unless_has(PRIV_CLUSTER);
            fcgi_volsizes();
        } else if(!strcmp(volume, ".mode")) {
            /* Switch cluster to read-only or to read-write mode (sxadm entry) - ADMIN required */
            fcgi_cluster_mode();
        } else if(!strcmp(volume, ".clusterMeta")) {
            /* Set cluster metadata - ADMIN required */
            fcgi_cluster_setmeta();
        } else if(!strcmp(volume, ".clusterSettings")) {
            /* Set cluster settings - ADMIN required */
            fcgi_cluster_settings();
        } else if(!strcmp(volume, ".requestVote")) { /* Raft RequestVote request handler */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_raft_request_vote();
        } else if(!strcmp(volume, ".appendEntries")) { /* Raft AppendEntries request handler */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_raft_append_entries();
        } else if(!strcmp(volume, ".jobspawn")) {
            /* Handle spawning local mass jobs, s2s only */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_mass_job_schedule();
        } else {
	    /* Create new volume - ADMIN required */
	    if(is_reserved())
		quit_errmsg(403, "Volume name is reserved");
	    fcgi_create_volume();
	}
	return;
    }

    if(verb == VERB_DELETE) {
	if(!strcmp(".rebalance", volume)) {
	    /* Complete rebalance process (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_stop_rebalance();
	} else if (!strcmp(volume, ".gc")) {
	    quit_unless_has(PRIV_ADMIN);
            sx_hashfs_gc_expire_all_reservations(hashfs);
            fcgi_trigger_gc();
	} else if(!strcmp(volume, ".dist")) {
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_revoke_distribution();
        } else if(!strcmp(volume, ".jlock")) {
	    /* Last resort "just unlock it" action for the jlock stuck case - sxadm entry */
	    quit_unless_has(PRIV_ADMIN);
	    fcgi_cluster_junlock();
	} else {
	    if(is_reserved())
		quit_errmsg(403, "Volume name is reserved");
            /* Delete volume - ADMIN or CLUSTER required */
            quit_unless_has(PRIV_ADMIN);
            fcgi_delete_volume();
	}
	return;
    }
}


void file_ops(void) {
    quit_unless_authed();

    if(verb != VERB_HEAD && verb != VERB_GET && verb != VERB_PUT && verb != VERB_DELETE) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\n");
	quit_errmsg(405, "Method not allowed");
    }

    if(verb == VERB_HEAD || verb == VERB_GET) {
	if(!strcmp(volume, ".data")) {
            if (has_arg("o")) {
                quit_unless_has(PRIV_CLUSTER);
                if (arg_is("o","check"))
                    fcgi_hashop_blocks(HASHOP_CHECK);
            } else {
                /* Get block content - any valid user allowed */
                fcgi_send_blocks();
            }
	} else if(!strcmp(volume, ".results")) {
	    /* Get job result - job owner or ADMIN required (enforcement in fcgi_job_result()) */
	    fcgi_job_result();
        } else if (!strcmp(volume, ".users")) {
	    /* Get user data - ADMIN required */
	    quit_unless_has(PRIV_ADMIN);
            fcgi_send_user();
        } else if(!strcmp(volume, ".challenge")) {
	    /* Response to challenge (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
            fcgi_challenge_response();
	} else if(!strcmp(volume, ".replfl")) {
	    /* Bulk file xfer (s2s, replacement node repopulation) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_send_replacement_files();
	} else {
	    /* Get file (meta)data - READ required */
	    quit_unless_has(PRIV_READ);
	    if(has_arg("fileMeta")) {
		/* Get file metadata */
		fcgi_send_file_meta();
	    } else if(has_arg("fileRevisions")) {
		/* Get available revisions for the requested file */
		fcgi_send_file_revisions();
	    } else {
		/* Get file content */
		fcgi_send_file();
	    }
	}
	return;
    }

    if(verb == VERB_PUT) {
	if(!strcmp(volume, ".upload")) {
	    if(content_len()) {
		/* Phase 1-extra (extend tempfile) - valid token required */
		fcgi_extend_tempfile();
	    } else {
		/* Phase 3 (flush tempfile) - valid token required */
		fcgi_flush_tempfile();
	    }
	    return;
	}

	if(!strcmp(volume, ".jlock") && !content_len()) {
	    /* Giant locking - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    if(content_len())
		quit_errmsg(400, "Invalid request");
	    fcgi_node_jlock();
	    return;
	}

	if(!strcmp(volume, ".users") && (arg_is("o","disable") || arg_is("o","enable"))) {
	    /* Enable/disable users (2pc/s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    if(content_len())
		quit_errmsg(400, "Invalid request");
	    fcgi_user_onoff(arg_is("o","enable"), has_arg("all"));
	    return;
	}

        if (!strcmp(".users", volume) && path && strlen(path) > 0) {
            rc_ty s;
            uint8_t requser[AUTH_UID_LEN];
            s = sx_hashfs_get_user_by_name(hashfs, path, requser, 0);
            switch(s) {
                case OK:
                    break;
                case ENOENT:
                    quit_errmsg(404, "No such user");
                case EINVAL:
                    quit_errnum(400);
                default:
                    quit_errnum(500);
            }
            /* user is allowed to change own key,
             * admin is allowed to change all keys */
            if (memcmp(requser, user, sizeof(requser))) {
                quit_unless_has(PRIV_ADMIN);
            }
            fcgi_user_modify();
            return;
        }

	if(!strcmp(volume, ".data")) {
            if (has_arg("o")) {
		/* Hashop reserve/inuse (s2s) - CLUSTER required */
                quit_unless_has(PRIV_CLUSTER);
                if (arg_is("o","reserve"))
                    fcgi_hashop_blocks(HASHOP_RESERVE);
                else if (arg_is("o", "revmod"))
                    fcgi_revision_op();
                else
                    quit_errmsg(400,"Invalid operation requested on hash batch");
                return;
            }
	    /* Phase 2 (blocks upload) - valid token required */
	    fcgi_save_blocks();
	    return;
	}

	if(!strcmp(volume, ".pushto")) {
	    /* Instruct this node to push some blocks to other nodes (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_push_blocks();
	    return;
	}

	if(!strcmp(volume, ".blockrevs")) {
	    /* Add or remove block revisions (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_blockrevs();
	    return;
	}

        if(!strcmp(volume, ".jobspawn")) {
            /* Handle committing local mass jobs, s2s only */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_mass_job_commit();
            return;
        }

	if(has_priv(PRIV_CLUSTER)) {
	    /* New file propagation (s2s) - CLUSTER required */
	    fcgi_create_file();
	} else {
	    /* Phase 1 (create tempfile) - WRITE required */
	    quit_unless_has(PRIV_WRITE);
	    fcgi_create_tempfile();
	}
	return;
    }

    if(verb == VERB_DELETE) {

	if(!strcmp(volume, ".jlock")) {
	    /* Giant unlocking - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_node_junlock();
	    return;
	}

	if(!strcmp(volume, ".users")) {
	    /* Delete user */
	    quit_unless_has(PRIV_ADMIN);
	    fcgi_delete_user();
	    return;
	}

	if(!strcmp(volume, ".faulty")) {
	    /* A faulty node was replaced - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_node_repaired();
	    return;
	}

	if(!strcmp(volume, ".data")) {
            if (has_arg("o")) {
		/* Hashop reserve/inuse (s2s) - CLUSTER required */
                quit_unless_has(PRIV_CLUSTER);
                if (arg_is("o", "revmod")) {
                    fcgi_revision_op();
                    return;
                }
            }
        }

	if(is_reserved())
            quit_errmsg(405, "Method Not Allowed");

	/* File deletion - WRITE required */
	quit_unless_has(PRIV_WRITE);
        fcgi_delete_file();
	return;
    }
}

/* Storage upgrade specific operations */
void upgrade_ops(void) {
    quit_unless_authed();

    if(verb != VERB_HEAD && verb != VERB_GET && verb != VERB_PUT && verb != VERB_DELETE) {
        CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\n");
        quit_errmsg(405, "Method not allowed");
    }

    /* Only allow requests coming directly from cluster */
    quit_unless_has(PRIV_CLUSTER);

    if(verb == VERB_GET && !strcmp(volume, ".upgrade_2_1_4")) {
        /* Volume files revision ID upgrade 2.1.3 -> 2.1.4 */
        fcgi_upgrade_2_1_4();
        return;
    }

    /* Fail with an appropriate error code when already upgraded node sends a not yet known upgrade query */
    quit_errmsg(501, "Method not implemented");
}

void job_2pc_handle_request(sxc_client_t *sx, const job_2pc_t *spec, void *yctx)
{
    if(spec->jpacts) {
	jparse_t *J = sxi_jparse_create(spec->jpacts, yctx, 0);
	rc_ty rc;
	int len;

	if(!J)
	    quit_errmsg(503, "Cannot create JSON parser");
	while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	    if(sxi_jparse_digest(J, hashbuf, len))
		break;
	if(len || sxi_jparse_done(J)) {
	    send_error(400, sxi_jparse_geterr(J));
	    sxi_jparse_destroy(J);
	    return;
	}
	sxi_jparse_destroy(J);

	auth_complete();
	quit_unless_authed();

	rc = spec->parse_complete ? spec->parse_complete(yctx) : OK;
	if(rc) {
            const char *msg = msg_get_reason();
            if(!msg || !*msg)
                msg = "Invalid request content";
            quit_errmsg(rc2http(rc), msg);
	}
    } else {
        /* check that body is empty? */
        auth_complete();
        quit_unless_authed();
    }

    job_t job = JOB_NOPARENT;
    rc_ty rc = sx_hashfs_job_new_2pc(hashfs, spec, yctx, uid, &job, has_priv(PRIV_CLUSTER));
    if (rc == OK) {
        if (has_priv(PRIV_CLUSTER))
            CGI_PUTS("\r\n");
        else
            send_job_info(job);
    } else {
        WARN("failed: %s", rc2str(rc));
        quit_errmsg(rc2http(rc), msg_get_reason());
    }
}

