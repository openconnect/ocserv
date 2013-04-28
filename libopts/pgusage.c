
/**
 * \file pgusage.c
 *
 *   Automated Options Paged Usage module.
 *
 * @addtogroup autoopts
 * @{
 */
/*
 *  This routine will run run-on options through a pager so the
 *  user may examine, print or edit them at their leisure.
 *
 *  This file is part of AutoOpts, a companion to AutoGen.
 *  AutoOpts is free software.
 *  AutoOpts is Copyright (C) 1992-2013 by Bruce Korb - all rights reserved
 *
 *  AutoOpts is available under any one of two licenses.  The license
 *  in use must be one of these two and the choice is under the control
 *  of the user of the license.
 *
 *   The GNU Lesser General Public License, version 3 or later
 *      See the files "COPYING.lgplv3" and "COPYING.gplv3"
 *
 *   The Modified Berkeley Software Distribution License
 *      See the file "COPYING.mbsd"
 *
 *  These files have the following sha256 sums:
 *
 *  8584710e9b04216a394078dc156b781d0b47e1729104d666658aecef8ee32e95  COPYING.gplv3
 *  4379e7444a0e2ce2b12dd6f5a52a27a4d02d39d247901d3285c88cf0d37f477b  COPYING.lgplv3
 *  13aa749a5b0a454917a944ed8fffc530b784f5ead522b1aacaf4ec8aa55a6239  COPYING.mbsd
 */

/*=export_func  optionPagedUsage
 * private:
 *
 * what:  Decipher a boolean value
 * arg:   + tOptions* + opts + program options descriptor +
 * arg:   + tOptDesc* + od   + the descriptor for this arg +
 *
 * doc:
 *  Run the usage output through a pager.
 *  This is very handy if it is very long.
 *  This is disabled on platforms without a working fork() function.
=*/
void
optionPagedUsage(tOptions * opts, tOptDesc * od)
{
#if ! defined(HAVE_WORKING_FORK)
    if ((od->fOptState & OPTST_RESET) != 0)
        return;

    (*opts->pUsageProc)(opts, EXIT_SUCCESS);
#else
    static pid_t     my_pid;
    char fil_name[1024];

    /*
     *  IF we are being called after the usage proc is done
     *     (and thus has called "exit(2)")
     *  THEN invoke the pager to page through the usage file we created.
     */
    switch (pagerState) {
    case PAGER_STATE_INITIAL:
    {
        if ((od->fOptState & OPTST_RESET) != 0)
            return;

        my_pid  = getpid();
        snprintf(fil_name, sizeof(fil_name), TMP_USAGE_FMT,
                 (unsigned long)my_pid);
        unlink(fil_name);

        /*
         *  Set usage output to this temporary file
         */
        option_usage_fp = fopen(fil_name, "w" FOPEN_BINARY_FLAG);
        if (option_usage_fp == NULL)
            _exit(EXIT_FAILURE);

        pagerState = PAGER_STATE_READY;

        /*
         *  Set up so this routine gets called during the exit logic
         */
        atexit((void(*)(void))optionPagedUsage);

        /*
         *  The usage procedure will now put the usage information into
         *  the temporary file we created above.
         */
        (*opts->pUsageProc)(opts, EXIT_SUCCESS);

        /* NOTREACHED */
        _exit(EXIT_FAILURE);
    }

    case PAGER_STATE_READY:
    {
        char const * pager  = (char const *)getenv(PAGER_NAME);

        /*
         *  Use the "more(1)" program if "PAGER" has not been defined
         */
        if (pager == NULL)
            pager = MORE_STR;

        /*
         *  Page the file and remove it when done.
         */
        snprintf(fil_name, sizeof(fil_name), PAGE_USAGE_FMT, pager,
                 (unsigned long)my_pid);
        fclose(stderr);
        dup2(STDOUT_FILENO, STDERR_FILENO);

        ignore_val( system( fil_name));
    }

    case PAGER_STATE_CHILD:
        /*
         *  This is a child process used in creating shell script usage.
         */
        break;
    }
#endif
}

/** @}
 *
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/pgusage.c */
