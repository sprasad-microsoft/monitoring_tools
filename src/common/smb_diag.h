/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Microsoft */
#ifndef __SMB_DIAG_H
#define __SMB_DIAG_H

#include "aod_diag.h"

#define MAX_SMB_COMMANDS	20

#define SMBSLOWER	 		0
#define MAX_SMB_STATUS_CODES	256
#define SMBIOSNOOP			1

struct smb_partial_event {
	__u16 smbcommand;
	union metrics metric;
	__u64 mid;
};

#endif /* __SMB_DIAG_H */