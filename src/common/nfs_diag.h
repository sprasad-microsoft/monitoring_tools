// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 Microsoft */
#ifndef __NFS_DIAG_H
#define __NFS_DIAG_H

#include "aod_diag.h"

#define MAX_NFS_COMMANDS        70
#define MAX_ERROR_CODES          113
// ignore the NFS4_OK

#define NFSSLOWER               10
#define NFSIOSNOOP                11

struct nfs_partial_event {
    __u16 nfscommand;
	union metrics metric;
};
// __u16 is sufficient for nfscommand, even though rpc_procinfo stores it as u32

int nfs4_errors[] = { 1, 2, 5, 6, 13, 17, 18, 20, 21, 22, 27, 28, 30, 31, 63, 66,
    69, 70, 10001, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011,
    10012, 10013, 10014, 10015, 10016, 10017, 10018, 10019, 10020, 10021, 10022,
    10023, 10024, 10025, 10026, 10027, 10028, 10029, 10030, 10031, 10032, 10033,
    10034, 10035, 10036, 10037, 10038, 10039, 10040, 10041, 10042, 10043, 10044,
    10045, 10046, 10047, 10048, 10049, 10050, 10051, 10052, 10053, 10054, 10055,
    10056, 10057, 10058, 10059, 10060, 10061, 10062, 10063, 10064, 10065, 10066,
    10067, 10068, 10069, 10070, 10071, 10072, 10074, 10075, 10076, 10077, 10078,
    10079, 10080, 10081, 10082, 10083, 10084, 10085, 10086, 10087, 10088, 10089,
    10090, 10091, 10092, 10093, 10094, 10095, 10096, 10097 };

#endif /* __NFS_DIAG_H */