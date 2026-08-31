#define _POSIX_C_SOURCE 200809L

#include "sqlite3.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum FaultMode {
  FAULT_NONE = 0,
  FAULT_SHORT_WRITE,
  FAULT_TORN_WRITE,
  FAULT_DATABASE_SYNC,
  FAULT_DIRECTORY_SYNC
} FaultMode;

typedef ssize_t (*PwriteFn)(int, const void *, size_t, off_t);

typedef struct FaultFile {
  sqlite3_file base;
  sqlite3_file *real;
  int open_flags;
} FaultFile;

static sqlite3_vfs fault_vfs;
static sqlite3_vfs *unix_vfs = NULL;
static PwriteFn original_pwrite = NULL;
static FaultMode fault_mode = FAULT_NONE;
static int fault_armed = 0;
static int fault_injections = 0;
static dev_t database_device = 0;
static ino_t database_inode = 0;

static int fault_close(sqlite3_file *file);
static int fault_read(sqlite3_file *file, void *buffer, int amount,
                      sqlite3_int64 offset);
static int fault_write(sqlite3_file *file, const void *buffer, int amount,
                       sqlite3_int64 offset);
static int fault_truncate(sqlite3_file *file, sqlite3_int64 size);
static int fault_sync(sqlite3_file *file, int flags);
static int fault_file_size(sqlite3_file *file, sqlite3_int64 *size);
static int fault_lock(sqlite3_file *file, int mode);
static int fault_unlock(sqlite3_file *file, int mode);
static int fault_check_reserved_lock(sqlite3_file *file, int *result);
static int fault_file_control(sqlite3_file *file, int operation, void *argument);
static int fault_sector_size(sqlite3_file *file);
static int fault_device_characteristics(sqlite3_file *file);

static const sqlite3_io_methods fault_io_methods = {
    1,
    fault_close,
    fault_read,
    fault_write,
    fault_truncate,
    fault_sync,
    fault_file_size,
    fault_lock,
    fault_unlock,
    fault_check_reserved_lock,
    fault_file_control,
    fault_sector_size,
    fault_device_characteristics,
};

static size_t real_file_offset(void) {
  size_t alignment = _Alignof(max_align_t);
  return (sizeof(FaultFile) + alignment - 1) & ~(alignment - 1);
}

static sqlite3_file *real_file(sqlite3_file *file) {
  return ((FaultFile *)file)->real;
}

static int fault_open(sqlite3_vfs *vfs, sqlite3_filename name,
                      sqlite3_file *file, int flags, int *out_flags) {
  sqlite3_vfs *real_vfs = (sqlite3_vfs *)vfs->pAppData;
  FaultFile *fault = (FaultFile *)file;
  sqlite3_file *real =
      (sqlite3_file *)((unsigned char *)file + real_file_offset());
  memset(fault, 0, sizeof(*fault));
  memset(real, 0, (size_t)real_vfs->szOsFile);
  int result =
      real_vfs->xOpen(real_vfs, name, real, flags, out_flags);
  if (result != SQLITE_OK) {
    return result;
  }
  fault->real = real;
  fault->open_flags = out_flags == NULL ? flags : *out_flags;
  fault->base.pMethods = &fault_io_methods;
  return SQLITE_OK;
}

static int fault_delete(sqlite3_vfs *vfs, const char *name, int sync_directory) {
  sqlite3_vfs *real_vfs = (sqlite3_vfs *)vfs->pAppData;
  if (fault_armed && fault_mode == FAULT_DIRECTORY_SYNC && sync_directory) {
    int result = real_vfs->xDelete(real_vfs, name, 0);
    if (result != SQLITE_OK) {
      return result;
    }
    fault_armed = 0;
    fault_injections += 1;
    return SQLITE_IOERR_DIR_FSYNC;
  }
  return real_vfs->xDelete(real_vfs, name, sync_directory);
}

static int fault_close(sqlite3_file *file) {
  sqlite3_file *real = real_file(file);
  int result = real->pMethods->xClose(real);
  file->pMethods = NULL;
  return result;
}

static int fault_read(sqlite3_file *file, void *buffer, int amount,
                      sqlite3_int64 offset) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xRead(real, buffer, amount, offset);
}

static int fault_write(sqlite3_file *file, const void *buffer, int amount,
                       sqlite3_int64 offset) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xWrite(real, buffer, amount, offset);
}

static int fault_truncate(sqlite3_file *file, sqlite3_int64 size) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xTruncate(real, size);
}

static int fault_sync(sqlite3_file *file, int flags) {
  FaultFile *fault = (FaultFile *)file;
  sqlite3_file *real = fault->real;
  if (fault_armed && fault_mode == FAULT_DATABASE_SYNC &&
      (fault->open_flags & SQLITE_OPEN_MAIN_DB) != 0) {
    fault_armed = 0;
    fault_injections += 1;
    errno = EIO;
    return SQLITE_IOERR_FSYNC;
  }
  return real->pMethods->xSync(real, flags);
}

static int fault_file_size(sqlite3_file *file, sqlite3_int64 *size) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xFileSize(real, size);
}

static int fault_lock(sqlite3_file *file, int mode) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xLock(real, mode);
}

static int fault_unlock(sqlite3_file *file, int mode) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xUnlock(real, mode);
}

static int fault_check_reserved_lock(sqlite3_file *file, int *result) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xCheckReservedLock(real, result);
}

static int fault_file_control(sqlite3_file *file, int operation, void *argument) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xFileControl(real, operation, argument);
}

static int fault_sector_size(sqlite3_file *file) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xSectorSize(real);
}

static int fault_device_characteristics(sqlite3_file *file) {
  sqlite3_file *real = real_file(file);
  return real->pMethods->xDeviceCharacteristics(real);
}

static int is_database_descriptor(int descriptor) {
  struct stat status;
  if (fstat(descriptor, &status) != 0) {
    return 0;
  }
  return status.st_dev == database_device && status.st_ino == database_inode;
}

static ssize_t fault_pwrite(int descriptor, const void *buffer, size_t amount,
                            off_t offset) {
  if (fault_armed &&
      (fault_mode == FAULT_SHORT_WRITE || fault_mode == FAULT_TORN_WRITE) &&
      is_database_descriptor(descriptor) && amount > 1) {
    size_t partial = amount / 2;
    ssize_t written = original_pwrite(descriptor, buffer, partial, offset);
    if (written < 0) {
      return written;
    }
    fault_armed = 0;
    fault_injections += 1;
    if (fault_mode == FAULT_TORN_WRITE) {
      _exit(86);
    }
    return written;
  }
  return original_pwrite(descriptor, buffer, amount, offset);
}

static int register_fault_vfs(void) {
  unix_vfs = sqlite3_vfs_find("unix");
  if (unix_vfs == NULL || unix_vfs->iVersion < 3 ||
      unix_vfs->xGetSystemCall == NULL || unix_vfs->xSetSystemCall == NULL) {
    return SQLITE_NOTFOUND;
  }
  fault_vfs = *unix_vfs;
  fault_vfs.pNext = NULL;
  fault_vfs.zName = "gantry-fault";
  fault_vfs.szOsFile = (int)(real_file_offset() + (size_t)unix_vfs->szOsFile);
  fault_vfs.pAppData = unix_vfs;
  fault_vfs.xOpen = fault_open;
  fault_vfs.xDelete = fault_delete;
  return sqlite3_vfs_register(&fault_vfs, 0);
}

static int install_pwrite_fault(void) {
  sqlite3_syscall_ptr pointer =
      unix_vfs->xGetSystemCall(unix_vfs, "pwrite");
  if (pointer == NULL) {
    return SQLITE_NOTFOUND;
  }
  original_pwrite = (PwriteFn)pointer;
  return unix_vfs->xSetSystemCall(unix_vfs, "pwrite",
                                  (sqlite3_syscall_ptr)fault_pwrite);
}

static void restore_pwrite(void) {
  if (unix_vfs != NULL && unix_vfs->xSetSystemCall != NULL &&
      original_pwrite != NULL) {
    unix_vfs->xSetSystemCall(unix_vfs, "pwrite", NULL);
  }
  original_pwrite = NULL;
}

static int execute(sqlite3 *database, const char *sql) {
  char *message = NULL;
  int result = sqlite3_exec(database, sql, NULL, NULL, &message);
  if (result != SQLITE_OK && message != NULL) {
    fprintf(stderr, "sqlite error %d: %s\n", result, message);
  }
  sqlite3_free(message);
  return result;
}

static int open_database(const char *path, sqlite3 **database) {
  return sqlite3_open_v2(path, database,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         "gantry-fault");
}

static int prepare_database(const char *path) {
  sqlite3 *database = NULL;
  int result = open_database(path, &database);
  if (result != SQLITE_OK) {
    sqlite3_close(database);
    return result;
  }
  result = execute(
      database,
      "PRAGMA journal_mode=DELETE;"
      "PRAGMA synchronous=EXTRA;"
      "PRAGMA mmap_size=0;"
      "CREATE TABLE journals (journal_id TEXT PRIMARY KEY NOT NULL, "
      "generation INTEGER NOT NULL, owner_token TEXT, committed_through "
      "INTEGER NOT NULL) STRICT;"
      "CREATE TABLE payloads (journal_id TEXT NOT NULL, payload_key TEXT NOT "
      "NULL, class TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY "
      "(journal_id, payload_key)) STRICT;"
      "CREATE TABLE evidence (journal_id TEXT NOT NULL, sequence INTEGER NOT "
      "NULL, evidence_id BLOB NOT NULL UNIQUE, kind TEXT NOT NULL, "
      "canonical_body BLOB NOT NULL, PRIMARY KEY (journal_id, sequence)) "
      "STRICT;"
      "CREATE TABLE evidence_references (journal_id TEXT NOT NULL, sequence "
      "INTEGER NOT NULL, ordinal INTEGER NOT NULL, evidence_id BLOB NOT NULL, "
      "PRIMARY KEY (journal_id, sequence, ordinal)) STRICT;"
      "CREATE TABLE evidence_payloads (journal_id TEXT NOT NULL, sequence "
      "INTEGER NOT NULL, ordinal INTEGER NOT NULL, payload_key TEXT NOT NULL, "
      "PRIMARY KEY (journal_id, sequence, ordinal)) STRICT;"
      "BEGIN IMMEDIATE;"
      "INSERT INTO journals VALUES ('fault-journal', 1, 'owner', 1);"
      "INSERT INTO payloads VALUES ('fault-journal', 'old-payload', "
      "'normalized-value', X'6f6c64');"
      "INSERT INTO evidence VALUES ('fault-journal', 1, "
      "X'0000000000000000000000000000000000000000000000000000000000000001', "
      "'fault-evidence/v1', X'7b226964223a226f6c64227d');"
      "COMMIT;");
  int close_result = sqlite3_close(database);
  return result == SQLITE_OK ? close_result : result;
}

static int run_fault_transaction(const char *path, FaultMode mode) {
  sqlite3 *database = NULL;
  int result = open_database(path, &database);
  if (result != SQLITE_OK) {
    sqlite3_close(database);
    return result;
  }
  result = execute(database,
                   "PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;"
                   "PRAGMA mmap_size=0;");
  if (result != SQLITE_OK) {
    sqlite3_close(database);
    return result;
  }
  struct stat status;
  if (stat(path, &status) != 0) {
    sqlite3_close(database);
    return SQLITE_IOERR;
  }
  database_device = status.st_dev;
  database_inode = status.st_ino;
  fault_mode = mode;
  fault_armed = 1;
  fault_injections = 0;
  if ((mode == FAULT_SHORT_WRITE || mode == FAULT_TORN_WRITE) &&
      install_pwrite_fault() != SQLITE_OK) {
    sqlite3_close(database);
    return SQLITE_NOTFOUND;
  }
  result = execute(
      database,
      "BEGIN IMMEDIATE;"
      "INSERT INTO payloads VALUES ('fault-journal', 'new-payload', "
      "'normalized-value', X'6e6577');"
      "INSERT INTO evidence VALUES ('fault-journal', 2, "
      "X'0000000000000000000000000000000000000000000000000000000000000002', "
      "'fault-evidence/v1', X'7b226964223a226e6577227d');"
      "UPDATE journals SET committed_through = 2 WHERE journal_id = "
      "'fault-journal';"
      "COMMIT;");
  restore_pwrite();
  fault_armed = 0;
  if (result != SQLITE_OK) {
    execute(database, "ROLLBACK;");
  }
  sqlite3_close(database);
  return result;
}

static int query_integer(sqlite3 *database, const char *sql, int *value) {
  sqlite3_stmt *statement = NULL;
  int result = sqlite3_prepare_v2(database, sql, -1, &statement, NULL);
  if (result == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW) {
    *value = sqlite3_column_int(statement, 0);
  } else if (result == SQLITE_OK) {
    result = SQLITE_ERROR;
  }
  sqlite3_finalize(statement);
  return result;
}

static int verify_database(const char *path, const char **state) {
  sqlite3 *database = NULL;
  int result = open_database(path, &database);
  if (result != SQLITE_OK) {
    sqlite3_close(database);
    return result;
  }
  sqlite3_stmt *check = NULL;
  result = sqlite3_prepare_v2(database, "PRAGMA quick_check(1)", -1, &check,
                              NULL);
  if (result != SQLITE_OK || sqlite3_step(check) != SQLITE_ROW ||
      strcmp((const char *)sqlite3_column_text(check, 0), "ok") != 0) {
    sqlite3_finalize(check);
    sqlite3_close(database);
    return SQLITE_CORRUPT;
  }
  sqlite3_finalize(check);

  int committed = 0;
  int evidence = 0;
  int payloads = 0;
  result = query_integer(
      database,
      "SELECT committed_through FROM journals WHERE journal_id='fault-journal'",
      &committed);
  if (result == SQLITE_OK) {
    result = query_integer(database,
                           "SELECT count(*) FROM evidence WHERE journal_id="
                           "'fault-journal'",
                           &evidence);
  }
  if (result == SQLITE_OK) {
    result = query_integer(database,
                           "SELECT count(*) FROM payloads WHERE journal_id="
                           "'fault-journal'",
                           &payloads);
  }
  sqlite3_close(database);
  if (result != SQLITE_OK) {
    return result;
  }
  if (committed == 1 && evidence == 1 && payloads == 1) {
    *state = "old";
    return SQLITE_OK;
  }
  if (committed == 2 && evidence == 2 && payloads == 2) {
    *state = "new";
    return SQLITE_OK;
  }
  return SQLITE_CORRUPT;
}

static FaultMode parse_mode(const char *name) {
  if (strcmp(name, "short-write") == 0) {
    return FAULT_SHORT_WRITE;
  }
  if (strcmp(name, "torn-write") == 0) {
    return FAULT_TORN_WRITE;
  }
  if (strcmp(name, "database-sync-failure") == 0) {
    return FAULT_DATABASE_SYNC;
  }
  if (strcmp(name, "directory-sync-failure") == 0) {
    return FAULT_DIRECTORY_SYNC;
  }
  return FAULT_NONE;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s CASE DATABASE\n", argv[0]);
    return 2;
  }
  FaultMode mode = parse_mode(argv[1]);
  if (mode == FAULT_NONE) {
    fprintf(stderr, "unknown fault case: %s\n", argv[1]);
    return 2;
  }
  if (strcmp(sqlite3_libversion(), "3.53.2") != 0) {
    fprintf(stderr, "unexpected SQLite engine: %s\n", sqlite3_libversion());
    return 3;
  }
  if (register_fault_vfs() != SQLITE_OK) {
    fprintf(stderr, "could not register the delegating fault VFS\n");
    return 4;
  }
  unlink(argv[2]);
  size_t journal_length = strlen(argv[2]) + sizeof("-journal");
  char *journal = malloc(journal_length);
  if (journal == NULL) {
    return 5;
  }
  snprintf(journal, journal_length, "%s-journal", argv[2]);
  unlink(journal);
  free(journal);
  if (prepare_database(argv[2]) != SQLITE_OK) {
    fprintf(stderr, "could not prepare the fault database\n");
    return 6;
  }

  int transaction_result = SQLITE_OK;
  const char *commit = "success";
  int injections = 0;
  if (mode == FAULT_TORN_WRITE) {
    pid_t child = fork();
    if (child < 0) {
      return 7;
    }
    if (child == 0) {
      int result = run_fault_transaction(argv[2], mode);
      _exit(result == SQLITE_OK ? 87 : 88);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 86) {
      fprintf(stderr, "torn-write child did not stop at the injected cut\n");
      return 8;
    }
    commit = "crash";
    injections = 1;
  } else {
    transaction_result = run_fault_transaction(argv[2], mode);
    injections = fault_injections;
    if (transaction_result != SQLITE_OK) {
      commit = "io-error";
    }
  }

  const char *state = NULL;
  if (verify_database(argv[2], &state) != SQLITE_OK || injections != 1) {
    fprintf(stderr, "fault case did not preserve an atomic old-or-new prefix\n");
    return 9;
  }
  if (mode == FAULT_SHORT_WRITE &&
      (transaction_result != SQLITE_OK || strcmp(state, "new") != 0)) {
    fprintf(stderr, "SQLite did not recover from the injected short write\n");
    return 10;
  }
  if (mode == FAULT_TORN_WRITE && strcmp(state, "old") != 0) {
    fprintf(stderr, "hot-journal recovery did not restore the old prefix\n");
    return 11;
  }
  if ((mode == FAULT_DATABASE_SYNC || mode == FAULT_DIRECTORY_SYNC) &&
      transaction_result == SQLITE_OK) {
    fprintf(stderr, "injected sync failure did not surface from commit\n");
    return 12;
  }

  printf("case=%s commit=%s state=%s injections=%d sqlite=%s\n", argv[1],
         commit, state, injections, sqlite3_libversion());
  return 0;
}
