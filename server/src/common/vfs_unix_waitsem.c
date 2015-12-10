/*
 * 2015 September 23
 *
 * The author disclaims copyright to this source code.  In place of
 * a legal notice, here is a blessing:
 *
 *    May you do good and not evil.
 *    May you find forgiveness for yourself and forgive others.
 *    May you share freely, never taking more than you give.
 *
 ************************************************************************
 *
 * This file contains a VFS "shim" - a layer that sits in between the
 * pager and the real VFS.
 *
 * This particular shim is based on test_quota.c and implements
 * timed waiting on locks.
 */

#include "config.h"
#if HAVE_DECL_CLOCK_GETTIME && HAVE_DECL_SEM_TIMEDWAIT

/* make asserts opt-in */
#if !defined(SQLITE_DEBUG)
# define NDEBUG 1
#endif

/* expose POSIX.1-2001 functions */
#define _XOPEN_SOURCE 600

#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <semaphore.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "sqlite3.h"

typedef struct {
  char *name;
  sem_t *sem;
  int held;
  unsigned ofst;
  sqlite3_file *dms_file;
} TimedLock;
static int timedlockOpen(TimedLock *lock, const char *dbname, int nLock, sqlite3_file *dms_file);
static void timedlockClose(TimedLock *lock, int deleteFlag);
/* static int timedlockTry(TimedLock *lock); */
static int timedlockAcquire(TimedLock *lock, unsigned nMaxWaitMilli);
static int timedlockRelease(TimedLock *lock);
static int timedlockHeld(TimedLock *lock);

/*
** The sqlite3_file object for this VFS
*/
typedef struct {
  sqlite3_file base;              /* Base class - must be first */
  char *zLocksName;
  sqlite3_file *locks;
  TimedLock waiting[SQLITE_SHM_NLOCK];
  int busy_timeout;
  volatile void *pShared;
  int last_ofst;
  int last_n;
  /* The underlying VFS sqlite3_file is appended to this object */
} waitsem_file;
static sqlite3_file *waitsemSubOpen(sqlite3_file *pFile);
static int waitsemAcquire(waitsem_file *p, int ofst, int n);
static int waitsemRelease(waitsem_file *p, int ofst, int n);

/*
  There are three problems to solve here:
   - writer starvation: if process A releases the xShmLock and soon tries to
   acquire it again it will succeed, even if other processes were waiting for
   the lock for a long time
   - xShmLock is a polling-based lock, meaning that wakeup can be delayed up to
     100ms from the optimal wakeup time
   - trying to acquire a SHARED lock after releasing an EXCLUSIVE lock in
   walTryBeginRead can be delayed for longer than the 323 ms allowed, causing
   SQLITE_PROTOCOL error:
       - the wal header could be paged out
       - a checkpoint might be running which holds all the reader locks too, if
       the checkpoint starts between releasing the EXCLUSIVE lock and acquiring
       the SHARED lock!
   Thus EXCLUSIVE -> UNLOCK -> SHARED should use the busy timeout too.

 Starvation in a reader-writer lock (cf. the 'third' readers-writers problem)
 can be solved by using an additional lock to ensure that you cannot obtain lock
 if another thread/process is already waiting for it:
   reader:
      noStarveLock.Wait()
      resource.ReadLock()
      noStarveLock.Signal()
      ...
      resource.Release()

   writer:
      noStarveLock.Wait()
      rc=resource.WriteLock()
        rc==SQLITE_BUSY -> noStarveLock.Release(); return
      ...
      resource.Release()
      noStarveLock.Release()

 Rewriting the pseudocode to show where xShmLock is called:
   reader:
      xShmLock(SQLITE_SHM_LOCK|SQLITE_SHM_SHARED):
         noStarveLock.Wait()
         rc=resource.ReadLock()
         noStarveLock.Signal()
         return rc

      xShmLock(SQLITE_SHM_UNLOCK|SQLITE_SHM_SHARED):
         return resource.Release()

   writer:
    xShmLock(SQLITE_SHM_LOCK|SQLITE_SHM_EXCLUSIVE):
        rc=noStarveLock.Wait()
         if (rc!=SQLITE_OK) -> return rc
        rc=resource.WriteLock()
         if (rc!=SQLITE_OK) -> noStarveLock.Release()
        return rc

    xShmLock(SQLITE_SHM_UNLOCK|SQLITE_SHM_EXCLUSIVE):
        rc=resource.Release()
        if (rc==SQLITE_OK) -> noStarveLock.Release()
        return rc

 This also helpes solve problem#2 when we are blocked due to a writer lock:
 noStarveLock can perform a timed wait and wakeup at the right time. The lock
 could be released immediately after the WriteLock is acquired, but then it
 couldn't be used for waiting, just to avoid starvation.

 Backwards compatibility with SQLite using the default VFS: if we use the
   underlying VFS's xShmLock for resource.*Lock() then we ensure that we do not
   corrupt the database (we hold the same locks that default SQLite would when
   making changes or reading from the DB) and are compatible with SQLite that
   does not use this custom VFS. If a default SQLite holds the xShmLock then
   we'll fall back to the busy handler.

 Lock usage in SQLite WAL:
   WRITE_LOCK - held exclusively by writers
   READ_LOCK(0)..READ_LOCK(NREADERS-1)
   - held exclusively by readers for a short time when updating a cursor,
   if it gets BUSY on one lock, it tries to acquire the next one
   - held as shared by readers
   - held exclusively by checkpoint

 It is desirable that we wait on tryEXCLUSIVE/EXCLUSIVE conflicts, and on
 trySHARED/EXCLUSIVE conflicts. It is not desirable that we wait on
 tryEXCLUSIVE/SHARED conflicts because this would prevent using more than one
 reader lock. The noStarveLock presented above has these properties: it only
 waits on conflict with an EXCLUSIVE lock, and very briefly on conflict with a
 SHARED lock (just for the duration of an attempt at acquiring the SHARED lock).

 Caveats: POSIX semaphores are not guaranteed to be FIFO, and have just 'weak
  semaphore semantics': starvation is still possible when more than 2 processes
  try to acquire a lock if 2 processes pass the lock to eachother. A strong
  semaphore could be constructed from weak semaphores using the Morris algorithm
  to prevent this.

 */

static int waitsemShmLock(
  sqlite3_file *pFile,       /* Database file holding the shared memory */
  int ofst,                  /* First lock to acquire or release */
  int n,                     /* Number of locks to acquire or release */
  int flags                  /* What to do with the lock */
){
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  waitsem_file *p = (waitsem_file*)pFile;
  int rc;

  if ( flags & SQLITE_SHM_LOCK ) {
    /* if there are others trying to acquire the lock: wait */
    rc = waitsemAcquire(p, ofst, n);
    if( rc!=SQLITE_OK ) return rc;
    /* we are the only one trying to acquire this lock with this VFS */
  }

  /* should invoke busy handler and wait on excl when shared lock is held,
     or use 2 semaphores to implement shared rwlock */
  rc = pSubOpen->pMethods->xShmLock(pSubOpen, ofst, n, flags);

  /* xShmLock could've failed if there were others with different VFS,
     or if we tried to acquire an EXCLUSIVE lock and others hold a SHARED lock
   */

  int nSharedLockMask = SQLITE_SHM_LOCK|SQLITE_SHM_SHARED;
  int nExclusiveUnlockMask = SQLITE_SHM_UNLOCK|SQLITE_SHM_EXCLUSIVE;

  if ( (rc!=SQLITE_OK) || /* unlock if we didn't acquire the real lock  */
       ((flags & nSharedLockMask) == nSharedLockMask) ||
       ((flags & nExclusiveUnlockMask) == nExclusiveUnlockMask) ) {
    waitsemRelease(p, ofst, n);
  }
  if( rc==SQLITE_BUSY ) {
    p->last_ofst=ofst;
    p->last_n=n;
  } else
    p->last_ofst=p->last_n=0;
  return rc;
}



/* simplified version of some functions from sqlite3.c */
static int unixLogError(int errcode, const char *func, const char *path){
  sqlite3_log(errcode, "%s(%s) - errno %d", func, path, errno);
  return errcode;
}

#ifndef NDEBUG
static int timedlockIsValid(TimedLock *lock){
  return lock && lock->sem && lock->sem!=SEM_FAILED && lock->name!=NULL && lock->dms_file && lock->dms_file->pMethods;
}
#endif

static int timedlockHeld(TimedLock *lock)
{
  assert( timedlockIsValid(lock) );
  return lock->held;
}

static int timedlockOpen(TimedLock *lock, const char *dbname, int nLock, sqlite3_file *dms_file){
  struct stat sb;

  assert(lock!=NULL);
  assert(dbname!=NULL);
  assert(dms_file!=NULL);
  memset(lock, 0, sizeof(*lock));
  if (stat(dbname, &sb)!=0)
    return unixLogError(SQLITE_IOERR_FSTAT, "stat", dbname);
  /* According to sem_open(3p) the name must start with slash,
     otherwise the effect is implementation defined */
  lock->name = sqlite3_mprintf("/etilqs-%d-%x-%x-%d", getuid(), sb.st_dev, sb.st_ino, nLock);
  if( lock->name==NULL )
    return SQLITE_NOMEM;

  lock->sem = sem_open(lock->name, O_CREAT, 0600, 1);
  if( lock->sem==SEM_FAILED ){
    sqlite3_free(lock->name);
    memset(lock, 0, sizeof(*lock));
    return unixLogError(SQLITE_NOMEM, "sem_open", lock->name);
  }

  lock->ofst=nLock;
  lock->dms_file=dms_file;
  return SQLITE_OK;
}

static void timedlockClose(TimedLock *lock, int deleteFlag){
  if (lock->sem != SEM_FAILED)
    sem_close(lock->sem);
  if (lock->name) {
    if (deleteFlag)
      sem_unlink(lock->name);
    sqlite3_free(lock->name);
  }
  memset(lock, 0, sizeof(*lock));
}

/*
static int timedlockTry(TimedLock *lock){
  assert(timedlockIsValid(lock));

  if( sem_trywait(lock->sem)!=0 ) {
    if( errno==EINTR || errno==EAGAIN ) return SQLITE_BUSY;
    return unixLogError(SQLITE_IOERR_LOCK, "sem_trywait", lock->name);
  }
  return SQLITE_OK;
}
*/

#define NS_IN_SEC 1000000000
#define NS_IN_MS (NS_IN_SEC / 1000)

static void timespec_add(struct timespec *t, unsigned nMilli)
{
  assert( t != NULL);
  t->tv_sec += nMilli / 1000;
  t->tv_nsec += (nMilli % 1000) * NS_IN_MS;
  /* normalize time */
  t->tv_sec += t->tv_nsec / NS_IN_SEC;
  t->tv_nsec = t->tv_nsec % NS_IN_SEC;
  assert(t->tv_sec > 0);
  assert(t->tv_nsec >= 0 && t->tv_nsec < NS_IN_SEC);
}

/*
Caveat: fcntl locking with SETLK is robust (in the pthread sense: automatically
  released when owner dies), however semaphores have kernel persistence and stay
  'locked' if the process ''acquiring' it dies. This could be solved by using an
  additional fcntl-based lock as a 'deadman' switch, and when the semaphore
  times out 'steal' ownership of it if we can acquire the deadman switch
  exclusively.

sem_open is limited to 14 characters on FreeBSD.
TODO: using xShmMmap to obtain additional shared memory and sem_init and
fcntl-based deadman switch would solve these problems.
*/
static int timedlockAcquire(TimedLock *lock, unsigned nMaxWaitMilli)
{
  struct timespec abs_timeout;
  int rc;
  assert( timedlockIsValid(lock) );
  assert( !timedlockHeld(lock) ) ;

  if ( clock_gettime(CLOCK_REALTIME, &abs_timeout)!=0 )
    return unixLogError(SQLITE_IOERR_LOCK, "clock_gettime", "");

  timespec_add(&abs_timeout, nMaxWaitMilli);
  if ( sem_timedwait(lock->sem, &abs_timeout)==0 ) {
    lock->held=1;
  } else {
    if ( errno==EINTR ) return SQLITE_BUSY;
    if ( errno!=ETIMEDOUT )
      return unixLogError(SQLITE_IOERR_LOCK, "sem_timedwait", lock->name);
    /* timeout: either another process/thread is holding the lock, or it crashed without posting it */
  }
  /* if we can acquire DMS then we own the lock */
  rc=lock->dms_file->pMethods->xShmLock(lock->dms_file, lock->ofst, 1, SQLITE_SHM_LOCK|SQLITE_SHM_EXCLUSIVE);
  if( rc!=SQLITE_OK ) {
    if( lock->held ) sem_post(lock->sem);
    lock->held=0;
  } else {
    lock->held=1;
  }
  return rc;
}

static int timedlockRelease(TimedLock *lock)
{
  assert( timedlockIsValid(lock) );
  assert( timedlockHeld(lock) ) ;
  if( sem_post(lock->sem) )
    return unixLogError(SQLITE_IOERR_LOCK, "sem_post", lock->name);
  lock->dms_file->pMethods->xShmLock(lock->dms_file, lock->ofst, 1, SQLITE_SHM_UNLOCK|SQLITE_SHM_EXCLUSIVE);
  lock->held=0;
  return SQLITE_OK;
}

/************************* Global Variables **********************************/
/*
** All global variables used by this file are containing within the following
** gWait structure.
*/
static struct {
  /* The pOrigVfs is the real, original underlying VFS implementation.
  ** Most operations pass-through to the real VFS.  This value is read-only
  ** during operation.  It is only modified at start-time and thus does not
  ** require a mutex.
  */
  sqlite3_vfs *pOrigVfs;

  /* The sThisVfs is the VFS structure used by this shim.  It is initialized
  ** at start-time and thus does not require a mutex
  */
  sqlite3_vfs sThisVfs;

  /* The sIoMethods defines the methods used by sqlite3_file objects
  ** associated with this shim.  It is initialized at start-time and does
  ** not require a mutex.
  **
  ** When the underlying VFS is called to open a file, it might return
  ** either a version 1 or a version 2 sqlite3_file object.  This shim
  ** has to create a wrapper sqlite3_file of the same version.  Hence
  ** there are two I/O method structures, one for version 1 and the other
  ** for version 2.
  */
  sqlite3_io_methods sIoMethodsV1;
  sqlite3_io_methods sIoMethodsV2;
  sqlite3_io_methods sIoMethodsV3;

  /* True when this shim as been initialized.
  */
  int isInitialized;

} gWait;

/* Translate an sqlite3_file* that is really a waitsem_file* into
** the sqlite3_file* for the underlying original VFS.
*/
static sqlite3_file *waitsemSubOpen(sqlite3_file *pFile){
  waitsem_file *p = (waitsem_file*)pFile;
  return (sqlite3_file*)&p[1];
}

/************************* VFS Method Wrappers *****************************/
/*
** This is the xOpen method used for this VFS.
**
** Most of the work is done by the underlying original VFS.
*/
static int waitsemOpen(
  sqlite3_vfs *pVfs,          /* This VFS */
  const char *zName,          /* Name of file to be opened */
  sqlite3_file *pFile,        /* Fill in this file descriptor */
  int flags,                  /* Flags to control the opening */
  int *pOutFlags              /* Flags showing results of opening */
){
    int rc;                                    /* Result code */
    waitsem_file *p = (waitsem_file*)pFile;   /* The new file descriptor */
    sqlite3_file *pSubOpen;                    /* Real file descriptor */
    sqlite3_vfs *pOrigVfs = gWait.pOrigVfs;   /* Real VFS */

    /* If the file is not a main database file then use the normal xOpen method
    */
    if( (flags & (SQLITE_OPEN_MAIN_DB))==0 ){
        /* TODO: posix_fallocate WAL file on create! how? */
        return pOrigVfs->xOpen(pOrigVfs, zName, pFile, flags, pOutFlags);
    }

    pSubOpen = waitsemSubOpen(pFile);
    rc = pOrigVfs->xOpen(pOrigVfs, zName, pSubOpen, flags, pOutFlags);
    if( rc==SQLITE_OK ){
        if( pSubOpen->pMethods->iVersion==1 ){
            p->base.pMethods = &gWait.sIoMethodsV1;
        }else if( pSubOpen->pMethods->iVersion ==2 ){
            p->base.pMethods = &gWait.sIoMethodsV2;
        }else{
          p->base.pMethods = &gWait.sIoMethodsV3;
        }

        if ( rc==SQLITE_OK ) {
          char *doublez;
          unsigned n;
          p->zLocksName = sqlite3_mprintf("%s-locks", zName);
          if( p->zLocksName ){
            /* SQLite wants double \0 terminated string */
            n  = strlen(p->zLocksName)+2;
            doublez = sqlite3_malloc(n);
            if( doublez ){
              memcpy(doublez, p->zLocksName, n-2);
              doublez[n-1]=doublez[n-2] = '\0';
            }else{
              rc = SQLITE_NOMEM;
            }
            sqlite3_free(p->zLocksName);
            p->zLocksName = doublez;
          }else{
            rc = SQLITE_NOMEM;
          }
        }

        if (rc != SQLITE_OK) {
            pSubOpen->pMethods->xClose(pSubOpen);
            return rc;
        }
    }
    return rc;
}

/************************ I/O Method Wrappers *******************************/

/* xClose requests get passed through to the original VFS.
 * But we also have to close our own struct */
static int waitsemClose(sqlite3_file *pFile)
{
    sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
    waitsem_file *p = (waitsem_file*)pFile;
    int rc = pSubOpen->pMethods->xClose(pSubOpen);
    if ( rc==SQLITE_OK ) {
      sqlite3_free(p->zLocksName);
      p->zLocksName=NULL;
    }
    return rc;
}

/* Pass requests to underlying VFS */
static int waitsemRead(
  sqlite3_file *pFile,
  void *pBuf,
  int iAmt,
  sqlite3_int64 iOfst)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xRead(pSubOpen, pBuf, iAmt, iOfst);
}

static int waitsemWrite(sqlite3_file *pFile,
                        const void *pBuf,
                        int iAmt,
                        sqlite3_int64 iOfst)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xWrite(pSubOpen, pBuf, iAmt, iOfst);
}

static int waitsemTruncate(sqlite3_file *pFile, sqlite3_int64 size)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xTruncate(pSubOpen, size);
}

static int waitsemSync(sqlite3_file *pFile, int flags)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xSync(pSubOpen, flags);
}

static int waitsemFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xFileSize(pSubOpen, pSize);
}

static int waitsemLock(sqlite3_file *pFile, int lock)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xLock(pSubOpen, lock);
}

static int waitsemUnlock(sqlite3_file *pFile, int lock)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xUnlock(pSubOpen, lock);
}

static int waitsemCheckReservedLock(sqlite3_file *pFile, int *pResOut)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xCheckReservedLock(pSubOpen, pResOut);
}

static int waitsemFileControl(sqlite3_file *pFile, int op, void *pArg)
{
  int rc;
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  waitsem_file *p = (waitsem_file*)pFile;
  /* intercept and save busy_timeout set via PRAGMA */
  if( op==SQLITE_FCNTL_PRAGMA ) {
    char **pragma = pArg;
    assert( pragma!=NULL && pragma[1]!=NULL);
    if( sqlite3_stricmp(pragma[1], "busy_timeout")==0 && pragma[2]!=NULL )
      p->busy_timeout = atoi(pragma[2])/2;
  }
  rc = pSubOpen->pMethods->xFileControl(pSubOpen, op, pArg);
  if( op==SQLITE_FCNTL_VFSNAME && rc==SQLITE_OK ){
    *(char**)pArg = sqlite3_mprintf("%s/%z", gWait.sThisVfs.zName, *(char**)pArg);
  }
  return rc;
}

static int waitsemSectorSize(sqlite3_file *pFile)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xSectorSize(pSubOpen);
}

static int waitsemDeviceCharacteristics(sqlite3_file *pFile)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xDeviceCharacteristics(pSubOpen);
}

static int waitsemShmMap(sqlite3_file *pFile,
                         int iRegion,
                         int szRegion,
                         int bExtend,
                         void volatile **pp)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  waitsem_file *p = (waitsem_file*)pFile;
  if ( !p->locks ) {
    sqlite3_vfs *pOrigVfs = gWait.pOrigVfs;
    unsigned i;
    int res = 0;
    int rc;
    int flags=SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_MAIN_DB;
    p->locks=sqlite3_malloc(pOrigVfs->szOsFile);
    if( !p->locks ) return SQLITE_NOMEM;
    rc = pOrigVfs->xOpen(pOrigVfs, p->zLocksName, p->locks, flags, &res);
    if ( rc!=SQLITE_OK ) {
      sqlite3_free(p->locks);
      p->locks=NULL;
      return rc;
    }

    for(i=0;i<sizeof(p->waiting)/sizeof(p->waiting[0]);i++) {
      rc = timedlockOpen(&p->waiting[i], p->zLocksName, i, p->locks);
      if (rc != SQLITE_OK) {
        while(i-->0)
          timedlockClose(&p->waiting[i], 0);
        break;
      }
    }

    if( rc == SQLITE_OK )
      rc=p->locks->pMethods->xShmMap(p->locks, 0, 4096, 4096, (volatile void**)&p->pShared);
    if( rc!=SQLITE_OK ) {
      for(i=0;i<sizeof(p->waiting)/sizeof(p->waiting[0]);i++) {
        timedlockClose(&p->waiting[i], 0);
      }
      p->locks->pMethods->xClose(p->locks);
      sqlite3_free(p->locks);
      p->locks=NULL;
      return rc;
    }
  }
  return pSubOpen->pMethods->xShmMap(pSubOpen, iRegion, szRegion, bExtend, pp);
}

static void waitsemShmBarrier(sqlite3_file *pFile)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  pSubOpen->pMethods->xShmBarrier(pSubOpen);
}

static int waitsemShmUnmap(sqlite3_file *pFile, int deleteFlag)
{
  unsigned i;
  waitsem_file *p = (waitsem_file*)pFile;
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  int rc = pSubOpen->pMethods->xShmUnmap(pSubOpen, deleteFlag);
  if(rc == SQLITE_OK) {
    for(i=0;i<sizeof(p->waiting)/sizeof(p->waiting[0]);i++)
      timedlockClose(&p->waiting[i], deleteFlag);
    if (!p->locks)
      return SQLITE_OK; /* nothing to unmap, because map failed */
    rc=p->locks->pMethods->xShmUnmap(p->locks, deleteFlag);
    if( rc==SQLITE_OK) {
      rc=p->locks->pMethods->xClose(p->locks);
      if( rc==SQLITE_OK ) {
        if( deleteFlag )
          rc=gWait.pOrigVfs->xDelete(gWait.pOrigVfs, p->zLocksName, 0);
        sqlite3_free(p->locks);
        p->locks=NULL;
      }
    }
  }
  return rc;
}

static int waitsemIsValid(int ofst, int n)
{
  return
    ofst >= 0 && ofst < SQLITE_SHM_NLOCK &&
    n >= 0 && ofst < SQLITE_SHM_NLOCK;
}

static int waitsemAcquire(waitsem_file *p, int ofst, int n)
{
  unsigned i;
  int rc, timeout = p->busy_timeout;
  assert( waitsemIsValid(ofst, n) );

  if( p->last_ofst!=ofst || p->last_n!=n )
    timeout = 0; /* checkpoint and non-repeated lock attempts should return busy immediately */

  for(i=ofst;i<ofst+n;i++) {
    rc = timedlockAcquire(&p->waiting[i], timeout);
    if( rc!=SQLITE_OK ) {
      while( i-- > ofst )
        timedlockRelease(&p->waiting[i]);
      return rc;
    }
  }
  return SQLITE_OK;
}

static int waitsemRelease(waitsem_file *p, int ofst, int n)
{
  unsigned i;
  int result = SQLITE_OK;
  assert( waitsemIsValid(ofst, n) );

  p->locks->pMethods->xShmLock(p->locks, ofst, n, SQLITE_SHM_UNLOCK|SQLITE_SHM_EXCLUSIVE);
  for(i=ofst;i<ofst+n;i++) {
    int rc;
    rc = timedlockRelease(&p->waiting[i]);
    if (rc != SQLITE_OK)
      result = rc;
  }
  return result;
}

static int waitsemFetch(sqlite3_file *pFile, sqlite3_int64 iOfst, int iAmt, void **pp)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xFetch(pSubOpen, iOfst, iAmt, pp);
}

static int waitsemUnfetch(sqlite3_file *pFile, sqlite3_int64 iOfst, void *p)
{
  sqlite3_file *pSubOpen = waitsemSubOpen(pFile);
  return pSubOpen->pMethods->xUnfetch(pSubOpen, iOfst, p);
}

/************************** Public Interfaces *****************************/
/*
** Initialize this VFS shim.  Use the VFS named zOrigVfsName
** as the VFS that does the actual work.  Use the default if
** zOrigVfsName==NULL.
**
** This VFS shim is named "unix-wait".  It will become the default
** VFS if makeDefault is non-zero.
**
** THIS ROUTINE IS NOT THREADSAFE.  Call this routine exactly once
** during start-up.
*/
int waitsem_register(const char *zOrigVfsName, int makeDefault){
  sqlite3_vfs *pOrigVfs;
  if (gWait.isInitialized)
      return SQLITE_MISUSE;
  pOrigVfs = sqlite3_vfs_find(zOrigVfsName);
  if (!pOrigVfs)
      return SQLITE_ERROR;
  assert(pOrigVfs != &gWait.sThisVfs);
  gWait.isInitialized = 1;
  gWait.pOrigVfs = pOrigVfs;
  gWait.sThisVfs = *pOrigVfs;
  gWait.sThisVfs.xOpen = waitsemOpen;
  gWait.sThisVfs.szOsFile += sizeof(waitsem_file);
  gWait.sThisVfs.zName = "unix-wait";
  gWait.sIoMethodsV1.iVersion = 1;
  gWait.sIoMethodsV1.xClose = waitsemClose;
  gWait.sIoMethodsV1.xRead = waitsemRead;
  gWait.sIoMethodsV1.xWrite = waitsemWrite;
  gWait.sIoMethodsV1.xTruncate = waitsemTruncate;
  gWait.sIoMethodsV1.xSync = waitsemSync;
  gWait.sIoMethodsV1.xFileSize = waitsemFileSize;
  gWait.sIoMethodsV1.xLock = waitsemLock;
  gWait.sIoMethodsV1.xUnlock = waitsemUnlock;
  gWait.sIoMethodsV1.xCheckReservedLock = waitsemCheckReservedLock;
  gWait.sIoMethodsV1.xFileControl = waitsemFileControl;
  gWait.sIoMethodsV1.xSectorSize = waitsemSectorSize;
  gWait.sIoMethodsV1.xDeviceCharacteristics = waitsemDeviceCharacteristics;
  gWait.sIoMethodsV2 = gWait.sIoMethodsV1;
  gWait.sIoMethodsV2.iVersion = 2;
  gWait.sIoMethodsV2.xShmMap = waitsemShmMap;
  gWait.sIoMethodsV2.xShmLock = waitsemShmLock;
  gWait.sIoMethodsV2.xShmBarrier = waitsemShmBarrier;
  gWait.sIoMethodsV2.xShmUnmap = waitsemShmUnmap;
  gWait.sIoMethodsV3 = gWait.sIoMethodsV2;
  gWait.sIoMethodsV3.iVersion = 3;
  gWait.sIoMethodsV3.xFetch = waitsemFetch;
  gWait.sIoMethodsV3.xUnfetch = waitsemUnfetch;
  return sqlite3_vfs_register(&gWait.sThisVfs, makeDefault);
  /* caveat: no version 3 methods */
}

/*
** Shutdown this VFS.
**
** All SQLite database connections must be closed before calling this
** routine.
**
** THIS ROUTINE IS NOT THREADSAFE.  Call this routine exactly once while
** shutting down in order to free the VFS.
*/
int waitsem_unregister(void){
    if (!gWait.isInitialized)
        return SQLITE_MISUSE;
    gWait.isInitialized = 0;
    sqlite3_vfs_unregister(&gWait.sThisVfs);
    memset(&gWait, 0, sizeof(gWait));
    return SQLITE_OK;
}
#else

#include "sqlite3.h"
int waitsem_register(const char *zOrigVfsName, int makeDefault)
{
  return SQLITE_NOTFOUND;
}

int waitsem_unregister(void)
{
  return SQLITE_NOTFOUND;
}
#endif
/* Local Variables: */
/* c-basic-offset: 2 */
/* indent-tabs-mode: nil */
/* End: */
