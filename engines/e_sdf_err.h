/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ESDF_ERR_H
# define HEADER_ESDF_ERR_H

# ifdef  __cplusplus
extern "C" {
# endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

static int ERR_load_ESDF_strings(void);
static void ERR_unload_ESDF_strings(void);
static void ERR_ESDF_error(int function, int reason, char *file, int line);
# define ESDFerr(f,r) ERR_ESDF_error((f),(r),OPENSSL_FILE,OPENSSL_LINE)

/* Error codes for the ESDF functions. */

/* Function codes. */
# define ESDF_F_SDF_OPEN_DEVICE                           100
# define ESDF_F_SDF_RAND_BYTES                            101

/* Reason codes. */
# define ESDF_R_OPEN_DEVICE_FAILURE                       100
# define ESDF_R_OPEN_SESSION_FAILURE                      101
# define ESDF_R_OPERATION_FAILURE                         102

# ifdef  __cplusplus
}
# endif
#endif